vi.mock("@/lib/auth", () => ({
	requireGatewayToken: vi.fn(),
	requireSession: async () => ({ role: "owner" }),
	canAdmin: (role: string) => role === "owner",
}));
vi.mock("@/lib/list-page-settings", async () => {
	const { default: source } = await import("@/db/plans.v3.json");
	return {
		getListPageSettings: async () => ({
			sizes: source.policy.web_list_page_sizes,
			defaulted: false,
		}),
	};
});
/**
 * `B-527` proof — `/datasets` no longer renders the `ComingSoon` stub, whose
 * copy had gone FALSE at HEAD (it told a tenant "Tracelane has no Datasets
 * feature … nothing is recorded, stored or run here" while
 * `annotation_routes.rs:2301` writes that tenant's `dataset_items` from the
 * in-app review flow). This follows the `EVL-02` three-state pattern
 * (`apps/web/app/experiments/page.tsx:61-90`) and the mocking pattern of
 * `apps/web/app/playground/page.test.tsx`: `@/lib/gateway` is mocked wholesale
 * (never a real network, `.claude/rules/testing.md`) and rendered with
 * `renderToStaticMarkup`.
 */

import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { beforeEach, describe, expect, it, vi } from "vitest";

const h = vi.hoisted(() => {
	class FakeGatewayError extends Error {
		readonly status: number;
		readonly body: Record<string, unknown> | null;
		constructor(
			status: number,
			message: string,
			body: Record<string, unknown> | null = null,
		) {
			super(message);
			this.status = status;
			this.body = body;
		}
	}
	return {
		gatewayGet: vi.fn(),
		FakeGatewayError,
	};
});

vi.mock("next/link", () => ({
	default: ({ href, children, ...rest }: Record<string, unknown>) =>
		createElement("a", { href, ...rest }, children as never),
}));

vi.mock("@/lib/gateway", () => ({
	gatewayGet: (...args: unknown[]) => h.gatewayGet(...(args as [string])),
	GatewayError: h.FakeGatewayError,
}));

import DatasetsPage from "./page";

beforeEach(() => {
	h.gatewayGet.mockReset();
});

const NEVER_SAY = "Tracelane has no Datasets feature";

describe("DatasetsPage — not entitled", () => {
	it("renders the locked state at 200, never the ComingSoon copy", async () => {
		h.gatewayGet.mockRejectedValue(
			new h.FakeGatewayError(403, "entitlement_required"),
		);
		const el = await DatasetsPage({ searchParams: Promise.resolve({}) });
		const html = renderToStaticMarkup(el);

		// React escapes the apostrophe as `&#x27;` in the static-markup output,
		// so the assertion avoids it rather than matching the raw entity.
		expect(html).toContain("included in this plan");
		expect(html).toContain("/settings/billing");
		expect(html).not.toContain(NEVER_SAY);
	});
});

describe("DatasetsPage — the gateway read fails", () => {
	it("renders 'could not load', never the empty state", async () => {
		h.gatewayGet.mockRejectedValue(new h.FakeGatewayError(503, "unreachable"));
		const el = await DatasetsPage({ searchParams: Promise.resolve({}) });
		const html = renderToStaticMarkup(el);

		// "load datasets" is unique to the failure copy ("Couldn't load
		// datasets") — apostrophe avoided, same reason as the locked-state test.
		expect(html.toLowerCase()).toContain("load datasets");
		expect(html).not.toContain("No datasets yet");
		expect(html).not.toContain(NEVER_SAY);
	});
});

describe("DatasetsPage — no datasets", () => {
	it("renders a neutral empty state, not ComingSoon", async () => {
		h.gatewayGet.mockResolvedValue({
			datasets: [],
			next_cursor: null,
			total: 0,
		});
		const el = await DatasetsPage({ searchParams: Promise.resolve({}) });
		const html = renderToStaticMarkup(el);

		expect(html).toContain("No datasets yet");
		expect(html).toContain("New dataset");
		expect(html).not.toContain("POST /v1/datasets");
		expect(html).not.toContain(NEVER_SAY);
	});
});

describe("DatasetsPage — populated", () => {
	it("renders one row per dataset, with its name and item count", async () => {
		h.gatewayGet.mockResolvedValue({
			datasets: [
				{
					dataset_id: "11111111-1111-1111-1111-111111111111",
					name: "golden-set-a",
					description: "",
					created_at_ms: 1_757_000_000_000,
					created_by: "user_1",
					items: 12,
					with_reference: 9,
					from_traces: 3,
				},
				{
					dataset_id: "22222222-2222-2222-2222-222222222222",
					name: "golden-set-b",
					description: "",
					created_at_ms: 1_757_100_000_000,
					created_by: "user_1",
					items: null,
					with_reference: null,
					from_traces: null,
				},
			],
			next_cursor: null,
			total: 2,
		});
		const el = await DatasetsPage({ searchParams: Promise.resolve({}) });
		const html = renderToStaticMarkup(el);

		expect(html).toContain("golden-set-a");
		expect(html).toContain("golden-set-b");
		expect(html).toContain("12");
		// a failed per-dataset count renders "—", never a fabricated "0"
		// (`DatasetDto.items` is `Option<u64>` — `dataset_routes.rs`'s own
		// comment: "Zero-vs-unknown, and on an evidence product it is the
		// expensive one").
		expect(html).toContain("—");
		expect(html).not.toContain(NEVER_SAY);
	});

	it("calls the gateway exactly once, for the datasets list", async () => {
		h.gatewayGet.mockResolvedValue({
			datasets: [],
			next_cursor: null,
			total: 0,
		});
		await DatasetsPage({ searchParams: Promise.resolve({}) });

		expect(h.gatewayGet).toHaveBeenCalledTimes(1);
		expect(h.gatewayGet).toHaveBeenCalledWith(
			expect.stringMatching(/^\/v1\/datasets(\?|$)/),
		);
	});
});

describe("DatasetsPage — the page title", () => {
	it("carries the t-h1 role, like the other pages (ADR-074)", async () => {
		h.gatewayGet.mockResolvedValue({
			datasets: [],
			next_cursor: null,
			total: 0,
		});
		const el = await DatasetsPage({ searchParams: Promise.resolve({}) });
		const html = renderToStaticMarkup(el);

		expect(html).toContain('class="t-h1');
		expect(html).toContain(">Datasets<");
	});
});
