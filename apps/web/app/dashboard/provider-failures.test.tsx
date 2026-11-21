// @vitest-environment jsdom
import { Children, type ReactNode, isValidElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { beforeEach, expect, it, vi } from "vitest";
const h = vi.hoisted(() => ({ read: vi.fn() }));
vi.mock("@/lib/metrics/fetch", () => ({ fetchProviderFailuresFor: h.read }));
vi.mock("@/db", () => ({ db: {} }));
vi.mock("@/lib/auth", () => ({
	requireSession: async () => ({ tenantId: "synthetic" }),
}));
vi.mock("@/lib/gateway", () => ({
	GatewayError: class extends Error {
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
const row = {
	provider: "provider-a",
	failed: 10,
	rate_limited: 3,
	server_error: 4,
	other: 1,
	unknown: 2,
};
const fixture = {
	totals: {
		...row,
		provider: "",
		captured_spans: 100,
		recorded_spans: 20,
		capped_spans: 1,
		provider_count: 1,
	},
	providers: [row],
	truncated: false,
	record_cap: 64,
};
function find(
	node: ReactNode,
): { type: (props: object) => Promise<ReactNode>; props: object } | undefined {
	for (const child of Children.toArray(node)) {
		if (!isValidElement<{ children?: ReactNode }>(child)) continue;
		if (
			typeof child.type === "function" &&
			child.type.name === "ProviderFailures"
		)
			return {
				type: child.type as (props: object) => Promise<ReactNode>,
				props: child.props,
			};
		const nested = find(child.props.children);
		if (nested) return nested;
	}
}
async function panel() {
	const page = await DashboardPage({
		searchParams: Promise.resolve({
			since: "2026-11-18T00:00:00Z",
			until: "2026-11-18T01:00:00Z",
		}),
	});
	const component = find(page);
	expect(
		component,
		"Overview must render the recorded-failure panel",
	).toBeDefined();
	if (!component) throw new Error("Missing recorded-failure panel");
	const root = document.createElement("div");
	root.innerHTML = renderToStaticMarkup(await component.type(component.props));
	return root;
}
beforeEach(() => {
	h.read.mockReset().mockResolvedValue(structuredClone(fixture));
});
it("shows recorded failures with known and unknown HTTP classes", async () => {
	const root = await panel();
	expect(root.textContent).toMatch(/recorded failed attempts/i);
	expect([...root.querySelectorAll("th")].map((n) => n.textContent)).toEqual([
		"Provider",
		"Failed",
		"429",
		"5xx",
		"Other",
		"Unknown",
	]);
	expect(
		[...root.querySelectorAll("tbody td")].map((n) => n.textContent),
	).toEqual(["provider-a", "10", "3", "4", "1", "2"]);
});
it("reports ledger capture and cap evidence without an all-call failure rate", async () => {
	const text = (await panel()).textContent ?? "";
	expect(text).toMatch(/20.*100.*captured/i);
	expect(text).toMatch(/1.*64/);
	expect(text).toMatch(/single.*omitted|omitted.*single/i);
	expect(text).not.toMatch(/%|TTFT|time.to.first.token|dollars saved/i);
});
it("names missing provider identity instead of using the final serving provider", async () => {
	h.read.mockResolvedValue({
		...fixture,
		providers: [{ ...row, provider: "" }],
	});
	expect((await panel()).textContent).toMatch(/unreported provider/i);
});
it("keeps an observed zero class as zero", async () => {
	h.read.mockResolvedValue({
		...fixture,
		providers: [{ ...row, rate_limited: 0 }],
	});
	expect((await panel()).querySelectorAll("tbody td")[2]?.textContent).toBe(
		"0",
	);
});
it("does not claim no failures when no failure records exist", async () => {
	h.read.mockResolvedValue({
		...fixture,
		totals: { ...fixture.totals, failed: 0 },
		providers: [],
	});
	const text = (await panel()).textContent ?? "";
	expect(text).toMatch(/no recorded failed attempts/i);
	expect(text).not.toMatch(/no provider failures|all requests succeeded/i);
});
it("does not label missing gateway support as an empty sample", async () => {
	h.read.mockResolvedValue(null);
	const text = (await panel()).textContent ?? "";
	expect(text).toMatch(/unavailable/i);
	expect(text).not.toMatch(/no recorded failed attempts/);
});
it("distinguishes denied access from unavailable data", async () => {
	h.read.mockRejectedValue(new GatewayError(403, "Synthetic denied"));
	const text = (await panel()).textContent ?? "";
	expect(text).toMatch(/access/i);
	expect(text).not.toMatch(/warming|retry|no recorded/i);
});
it("does not suppress unexpected programming failures", async () => {
	const error = new TypeError("Synthetic unexpected");
	h.read.mockRejectedValue(error);
	await expect(panel()).rejects.toBe(error);
});
it("labels provider-row truncation without changing global totals", async () => {
	h.read.mockResolvedValue({ ...fixture, truncated: true });
	expect((await panel()).textContent).toMatch(/top|subset/i);
});
it("forwards the selected window to the metric read", async () => {
	await panel();
	expect(h.read.mock.calls[0]?.[0]).toMatchObject({
		sinceMs: Date.parse("2026-11-18T00:00:00Z"),
		untilMs: Date.parse("2026-11-18T01:00:00Z"),
	});
});
