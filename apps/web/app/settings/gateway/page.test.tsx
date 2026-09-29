import { renderToStaticMarkup } from "react-dom/server";
import { expect, it, vi } from "vitest";
const h = vi.hoisted(() => ({ status: 0 }));
vi.mock("@/lib/gateway", () => {
	class GatewayError extends Error {
		constructor(public status: number) {
			super("failure");
		}
	}
	return {
		GatewayError,
		gatewayGet: async () => {
			throw new GatewayError(h.status);
		},
	};
});
import {
	type GatewaySettings,
	GatewaySettingsView,
} from "./GatewaySettingsView";
import Page from "./page";
const data: GatewaySettings = {
	cache: {
		suspended: false,
		enabled: false,
		operator_ttl_hours: null,
		plan_ttl_hours: 0,
		configurable: false,
		threshold: null,
		max_scan_entries: null,
	},
	limits: {
		available: false,
		rate_limit_rpm: null,
		workspace_budget_micro_usd: null,
		spend_ceiling_micro_usd: null,
	},
	routing: {
		aliases: [],
		native: [],
		catalog: [{ provider: "last-provider", prefixes: ["last/"] }],
	},
	failover: { opt_in: true, retries: 0, backoff_ms: 0, chain: [] },
};
it("shows disabled cache, unknown caps and every supplied mapping without fake usage", () => {
	const html = renderToStaticMarkup(<GatewaySettingsView data={data} />);
	expect(html).toContain("Disabled by the operator");
	expect(html).toContain("Entitlements unavailable");
	expect(html).toContain("last-provider");
	expect(html).toContain("bypass");
	expect(html).toContain("0 hours");
	expect(html).not.toContain("$0.00");
});
it.each([
	[401, "Sign in to continue"],
	[403, "Access denied"],
	[503, "Couldn&#x27;t load gateway settings"],
])("preserves read status %s", async (status, text) => {
	h.status = Number(status);
	expect(renderToStaticMarkup(await Page())).toContain(text);
});
it("renders no <main> of its own — the app shell owns the one main landmark (B-587)", () => {
	const html = renderToStaticMarkup(<GatewaySettingsView data={data} />);
	expect(html).not.toMatch(/<main[\s>]/);
});
