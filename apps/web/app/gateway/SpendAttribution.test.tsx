import type { CostBreakdown } from "@/lib/gateway-ops";
import { createElement as h } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { SpendAttribution } from "./SpendAttribution";

/**
 * CX-27 / B-526 — the spend table is capped at the gateway's row cap, and until
 * this test the totals above it were summed over the CAPPED rows: a tenant with
 * more keys than the cap read a total that silently excluded the cheapest keys,
 * and — because zero-cost / unpriced groups sort LAST — the unpriced badge, the
 * one honesty control on the panel, was the first thing truncation deleted.
 *
 * The gateway now reports `group_count` (every group in the window, counted
 * before the LIMIT) and `truncated`; the panel must SAY when the table is a
 * subset so the total is never read as "these rows add up to this".
 */
const fixture: CostBreakdown = {
	window_hours: 24,
	by: "key",
	total_cost_usd: 12.5,
	total_requests: 1_000,
	priced_requests: 1_000,
	unpriced_requests: 0,
	group_count: 1,
	truncated: false,
	attribution_begins_note: null,
	scope: "all",
	eval_cost_usd: 0,
	eval_requests: 0,
	production_cost_usd: 12.5,
	production_requests: 1_000,
	eval_attribution_note: "n/a",
	rows: [
		{
			dimension: "0f9e8d7c-0000-0000-0000-000000000000",
			requests: 1_000,
			priced_requests: 1_000,
			unpriced_requests: 0,
			cost_usd: 12.5,
			input_tokens: 10,
			output_tokens: 10,
			eval_requests: 0,
			eval_cost_usd: 0,
		},
	],
};

function render(data: CostBreakdown): string {
	return renderToStaticMarkup(
		h(SpendAttribution, {
			data,
			by: "key",
			hrefFor: (by) => `/gateway?by=${by}`,
		}),
	);
}

describe("SpendAttribution — the truncation badge (CX-27)", () => {
	it("says the table is a subset when the gateway reports truncation", () => {
		const html = render({ ...fixture, truncated: true, group_count: 150 });
		expect(html).toContain("of 150");
		// The totals still cover every group — the badge must say so, or a reader
		// will add the visible rows and get a different number than the total.
		expect(html).toMatch(/totals cover all 150/);
	});

	it("renders no truncation badge when every group fits", () => {
		const html = render(fixture);
		expect(html).not.toContain("of 1 ");
		expect(html).not.toMatch(/totals cover all/);
	});
});

// SET-38 B5 / B-586 half 3: the spend row showed the key's INTERNAL id (8 chars of a UUID);
// it must read `name · prefix…` with a lifecycle suffix, and fall back honestly.
describe("spend rows are labelled by the key's name and public prefix", () => {
	const id = "0f9e8d7c-0000-0000-0000-000000000000";
	const html = (
		keyLabels?: Record<
			string,
			{
				name: string;
				prefix: string;
				state: "revoked" | "retiring" | "expired" | null;
			}
		>,
	) =>
		renderToStaticMarkup(
			h(SpendAttribution, {
				data: fixture,
				hrefFor: () => "#",
				by: "key",
				keyLabels,
			}),
		);
	it("a known key reads name · prefix", () => {
		const out = html({
			[id]: { name: "ci-nightly", prefix: "tlane_ab12cd", state: null },
		});
		expect(out).toContain("ci-nightly · tlane_ab12cd…");
		expect(out).not.toContain("0f9e8d7c…");
	});
	it("a revoked key says so", () => {
		expect(
			html({ [id]: { name: "old", prefix: "tlane_zz", state: "revoked" } }),
		).toContain("(revoked)");
	});
	it("an id with no matching key falls back to the short id and says why", () => {
		const out = html({});
		expect(out).toContain("0f9e8d7c…");
		expect(out).toContain("key not found in this workspace");
	});
});

it("links a key spend row to its editable settings deep link", () => {
	expect(render(fixture)).toContain(
		"/settings/api-keys?key=0f9e8d7c-0000-0000-0000-000000000000",
	);
});
