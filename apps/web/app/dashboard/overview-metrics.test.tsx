import type { CostBreakdown, GatewayStats } from "@/lib/gateway-ops";
import type { LatencyBreakdown } from "@/lib/latency";
import type { TimeRange } from "@/lib/metrics/time-range";
// @vitest-environment jsdom
/** Synthetic read-boundary fixtures; no database, credentials, or gateway calls.
 * These contracts are authored before implementation. Execution is pending an
 * authorized dependency restore; their presence is not evidence of a red run.
 */
import { Children, type ReactNode, isValidElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { beforeEach, describe, expect, it, vi } from "vitest";

const reads = vi.hoisted(() => ({
	fetchCostBreakdownFor: vi.fn(),
	fetchGatewayStatsFor: vi.fn(),
	fetchGuardrailStatsFor: vi.fn(),
	fetchLatencyBreakdownFor: vi.fn(),
	fetchSignaturesFor: vi.fn(),
	fetchSloRows: vi.fn(),
	fetchSloSummary: vi.fn(),
	fetchSloTimeseries: vi.fn(),
	fetchToolAnalyticsFor: vi.fn(),
	fetchWorkspaceGlance: vi.fn(),
}));
vi.mock("@/lib/metrics/fetch", () => reads);
vi.mock("@/lib/auth", () => ({
	requireSession: async () => ({ tenantId: "synthetic-org" }),
}));
vi.mock("@/db", () => ({
	db: {
		select: () => {
			throw new Error("Use default plan target in this fixture");
		},
	},
}));
vi.mock("@/lib/gateway", () => ({
	GatewayError: class GatewayError extends Error {
		constructor(
			public status: number,
			message: string,
		) {
			super(message);
		}
	},
}));
import { GatewayError } from "@/lib/gateway";
import DashboardPage from "./page";

const gateway: GatewayStats = {
	window_hours: 6,
	total_requests: 1000,
	total_errors: 0,
	error_rate_pct: 0,
	cache_hit_rate_pct: 75,
	provider_count: 1,
	total_failovers: 0,
	total_cost_usd: 0,
	rate_limited_since_start: 0,
	budget_exceeded_since_start: 0,
	open_breakers: 0,
	providers: [],
	uninstrumented: [],
};
const priced: CostBreakdown = {
	window_hours: 6,
	by: "provider",
	total_cost_usd: 0,
	total_requests: 1000,
	priced_requests: 1000,
	unpriced_requests: 0,
	group_count: 1,
	truncated: false,
	attribution_begins_note: null,
	scope: "all",
	eval_cost_usd: 0,
	eval_requests: 0,
	production_cost_usd: 0,
	production_requests: 1000,
	eval_attribution_note: "",
	rows: [],
};
const measured: LatencyBreakdown = {
	window_hours: 6,
	cache_hit_samples: 20,
	overhead_samples: 80,
	overhead_p50_ms: 5,
	overhead_p95_ms: 10,
	overhead_p99_ms: 15,
	provider_p50_ms: 100,
	provider_p95_ms: 190,
	provider_p99_ms: 300,
	ttft_p50_ms: 0,
	ttft_p95_ms: 0,
	ttft_p99_ms: 0,
	ttft_samples: 0,
	by_model: [],
};

beforeEach(() => {
	for (const read of Object.values(reads))
		read.mockReset().mockResolvedValue(null);
	reads.fetchGatewayStatsFor.mockResolvedValue({ ...gateway });
	reads.fetchCostBreakdownFor.mockResolvedValue({ ...priced });
	reads.fetchLatencyBreakdownFor.mockResolvedValue({ ...measured });
	reads.fetchSloRows.mockResolvedValue([]);
	reads.fetchSloTimeseries.mockResolvedValue([]);
	reads.fetchSloSummary.mockResolvedValue({
		requests: 1000,
		errors: 0,
		p50_ms: 105,
		p95_ms: 200,
		p99_ms: 315,
	});
});

// Follow the existing active-keys.test.tsx pattern: resolve only the server
// Activity subtree, leaving unrelated workspace/key reads outside this test.
function findActivity(node: ReactNode):
	| {
			render: (props: { range: TimeRange }) => Promise<ReactNode>;
			props: { range: TimeRange };
	  }
	| undefined {
	for (const child of Children.toArray(node)) {
		if (!isValidElement<{ children?: ReactNode; range: TimeRange }>(child))
			continue;
		if (
			typeof child.type === "function" &&
			child.type.name === "DashboardData"
		) {
			return {
				render: child.type as (props: {
					range: TimeRange;
				}) => Promise<ReactNode>,
				props: child.props,
			};
		}
		const found = findActivity(child.props.children);
		if (found) return found;
	}
}
async function activity() {
	const page = await DashboardPage({
		searchParams: Promise.resolve({
			since: "2026-11-18T08:00:00Z",
			until: "2026-11-18T14:00:00Z",
		}),
	});
	const component = findActivity(page);
	if (!component)
		throw new Error("Overview Activity server component was not found");
	const container = document.createElement("div");
	container.innerHTML = renderToStaticMarkup(
		await component.render(component.props),
	);
	return container;
}
function text(node: Element) {
	return (node.textContent ?? "").replace(/\s+/g, " ").trim();
}
function metric(root: Element, label: RegExp) {
	const leaf = [...root.querySelectorAll("*")].find((node) =>
		label.test(
			[...node.childNodes]
				.filter((child) => child.nodeType === 3)
				.map((child) => child.textContent)
				.join("")
				.trim(),
		),
	);
	if (!leaf) throw new Error(`Missing metric label ${label}`);
	const card =
		leaf.closest("a, article, section") ?? leaf.parentElement?.parentElement;
	if (!card) throw new Error(`Missing metric container ${label}`);
	return text(card);
}

describe("Overview metric semantics", () => {
	it("names provider prompt caching separately from response reuse", async () => {
		expect(metric(await activity(), /prompt.cache/i)).toMatch(/75(?:\.0+)?%/);
	});
	it("uses hits plus measured dispatched requests, not all gateway requests, for response cache share", async () => {
		const cache = metric(await activity(), /^response.cache/i);
		expect(cache).toMatch(/20(?:\.0+)?%/);
		expect(cache).toMatch(/20/);
		expect(cache).toMatch(/100\b/);
		expect(cache).toMatch(/measured/i);
		expect(cache).not.toMatch(/2(?:\.0+)?%/);
	});
	it("shows measured zero response hits as zero percent", async () => {
		reads.fetchLatencyBreakdownFor.mockResolvedValue({
			...measured,
			cache_hit_samples: 0,
			overhead_samples: 100,
		});
		expect(metric(await activity(), /^response.cache/i)).toMatch(
			/\b0(?:\.0+)?%/,
		);
	});
	it.each([undefined, 0])(
		"does not claim zero percent when eligible sample evidence is %s",
		async (hits) => {
			reads.fetchLatencyBreakdownFor.mockResolvedValue({
				...measured,
				cache_hit_samples: hits,
				overhead_samples: 0,
			});
			const cache = metric(await activity(), /^response.cache/i);
			expect(cache).not.toMatch(/\b0(?:\.0+)?%/);
			expect(cache).toMatch(/—|unknown|unavailable|no measured/i);
		},
	);
	it("does not treat older responses missing the hit counter as measured misses", async () => {
		const { cache_hit_samples: _hits, ...older } = measured;
		reads.fetchLatencyBreakdownFor.mockResolvedValue(older);
		expect(metric(await activity(), /^response.cache/i)).not.toMatch(
			/\b0(?:\.0+)?%/,
		);
	});
	it("shows a known priced zero as USD zero", async () => {
		expect(metric(await activity(), /^spend(?: \(est\.\))?$/i)).toMatch(
			/\$0(?:\.00)?\b/,
		);
	});
	it("distinguishes missing prices from free priced traffic", async () => {
		reads.fetchCostBreakdownFor.mockResolvedValue({
			...priced,
			priced_requests: 0,
			unpriced_requests: 1000,
		});
		const spend = metric(await activity(), /^spend(?: \(est\.\))?$/i);
		expect(spend).toMatch(/unpriced|missing pric|pricing unavailable/i);
		expect(spend).not.toMatch(/\$0(?:\.00)?\b/);
	});
	it("labels partial priced spend as a lower bound with unpriced coverage", async () => {
		reads.fetchGatewayStatsFor.mockResolvedValue({
			...gateway,
			total_cost_usd: 12,
		});
		reads.fetchCostBreakdownFor.mockResolvedValue({
			...priced,
			total_cost_usd: 12,
			priced_requests: 800,
			unpriced_requests: 200,
		});
		const spend = metric(await activity(), /^spend(?: \(est\.\))?$/i);
		expect(spend).toMatch(/lower bound|at least/i);
		expect(spend).toMatch(/200.*unpriced|unpriced.*200/i);
	});
	it("does not invent a priced zero when the pricing read is unavailable", async () => {
		reads.fetchCostBreakdownFor.mockResolvedValue(null);
		const spend = metric(await activity(), /^spend(?: \(est\.\))?$/i);
		expect(spend).not.toMatch(/\$0(?:\.00)?\b/);
		expect(spend).toMatch(/unavailable|waiting|unknown|—/i);
	});
	it("renders a permission explanation instead of a warming state for forbidden usage", async () => {
		reads.fetchGatewayStatsFor.mockRejectedValue(
			new GatewayError(403, "Synthetic denied"),
		);
		expect(text(await activity())).toMatch(/access|permission|administrator/i);
	});
	it("keeps authorized spend visible when trace metrics are forbidden", async () => {
		reads.fetchSloRows.mockRejectedValue(
			new GatewayError(403, "Synthetic denied"),
		);
		reads.fetchSloSummary.mockRejectedValue(
			new GatewayError(403, "Synthetic denied"),
		);
		const root = await activity();
		expect(metric(root, /^spend(?: \(est\.\))?$/i)).toMatch(/\$0(?:\.00)?\b/);
		expect(text(root)).toMatch(/access|permission|administrator/i);
	});
	it("does not describe permission-denied families as warming, empty or retryable", async () => {
		for (const [name, fetch] of Object.entries(reads)) {
			if (name !== "fetchCostBreakdownFor")
				fetch.mockRejectedValue(new GatewayError(403, "Synthetic denied"));
		}
		const root = await activity();
		expect(text(root)).toMatch(/access denied/i);
		expect(text(root)).not.toMatch(
			/warming|waiting on the gateway|retry|no traffic yet|connect a provider|configure guardrails/i,
		);
	});
	it("does not call unavailable traffic an empty measured window", async () => {
		reads.fetchSloRows.mockResolvedValue(null);
		reads.fetchSloSummary.mockResolvedValue(null);
		const root = await activity();
		const traffic = [...root.querySelectorAll("section")].filter((section) =>
			["Health at a glance", "Models, providers and failures"].includes(
				section.getAttribute("aria-label") ?? "",
			),
		);
		expect(traffic).toHaveLength(2);
		for (const section of traffic)
			expect(text(section)).not.toMatch(/no traffic yet/i);
	});
	it("removes the duplicated Request flow and percentile contribution framing", async () => {
		const content = text(await activity());
		expect(content).not.toMatch(
			/request flow|% of the trip|where the time goes/i,
		);
	});
	it("retains one availability headline and an SLO drilldown with the selected UTC window", async () => {
		const root = await activity();
		const labels = [...root.querySelectorAll("*")].filter((node) =>
			/^availability$/i.test(
				[...node.childNodes]
					.filter((child) => child.nodeType === 3)
					.map((child) => child.textContent)
					.join("")
					.trim(),
			),
		);
		expect(labels).toHaveLength(1);
		const links = [
			...root.querySelectorAll<HTMLAnchorElement>('a[href^="/slo?"]'),
		];
		expect(links.length).toBeGreaterThan(0);
		for (const link of links) {
			const url = new URL(
				link.getAttribute("href") ?? "",
				"https://synthetic.invalid",
			);
			expect(url.searchParams.get("since")).toBe("2026-11-18T08:00:00.000Z");
			expect(url.searchParams.get("until")).toBe("2026-11-18T14:00:00.000Z");
		}
	});
	it("does not claim dollars saved from response cache hit counts", async () => {
		expect(text(await activity())).not.toMatch(
			/dollars saved|\$[\d.,]+ saved|cost savings/i,
		);
	});
});
