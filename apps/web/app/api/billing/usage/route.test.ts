/**
 * Tests for GET /api/billing/usage — a PURE PASSTHROUGH (spec `BILL-01` §2.6,
 * §2.5b: ONE gateway call per load). No DB, no re-shaping — the body and
 * status the gateway returns are forwarded verbatim; a network failure maps
 * to 502. Negative cases (network failure) first per `.claude/rules/testing.md`.
 */

import { afterEach, describe, expect, it, vi } from "vitest";

vi.mock("@/lib/auth", () => ({
	requireGatewayToken: vi.fn(async () => ({ token: "minted-jwt" })),
}));

import { GET } from "./route";

const FIXTURE_USAGE = {
	month: "2026-09",
	computed_at: "2026-09-13T04:00:00Z",
	rates_available: true,
	rate_card_version: "v3",
	spend_ceiling_usd: null,
	overflow_mode: "auto_age",
	projected_overage_usd: null,
	ceiling_reached: false,
	warn_pct: [75, 90],
	meters: {
		ingest: {
			used: 182,
			included: 300,
			burst_exempt: 0,
			overage_units: 0,
			overage_usd: null,
			projection_month_end: 268,
			last_computed_at: null,
			unit: "GB",
		},
	},
	plan: {
		lookup_key: "team_v1",
		price_monthly_usd: 229,
		price_annual_month_usd: 190,
		price_from_usd: null,
		indexed_window_days: 90,
		queryable_days: 730,
		ledger_days: 730,
		unlimited_seats: true,
		f_sso: true,
	},
	rates: {},
};

describe("GET /api/billing/usage", () => {
	afterEach(() => {
		vi.unstubAllGlobals();
	});

	it("GRACEFUL: a network failure maps to 502, never throws", async () => {
		vi.stubGlobal(
			"fetch",
			vi.fn(async () => {
				throw new Error("ECONNREFUSED");
			}),
		);
		const res = await GET();
		expect(res.status).toBe(502);
	});

	it("PASSTHROUGH: forwards a gateway error STATUS verbatim (e.g. 503)", async () => {
		vi.stubGlobal(
			"fetch",
			vi.fn(
				async (..._args: unknown[]) =>
					({
						ok: false,
						status: 503,
						text: async () => JSON.stringify({ error: "metering unavailable" }),
					}) as unknown as Response,
			),
		);
		const res = await GET();
		expect(res.status).toBe(503);
		expect(await res.json()).toEqual({ error: "metering unavailable" });
	});

	it("PASSTHROUGH: forwards the six-meter body VERBATIM — no {plan, usage} wrapper, no re-shaping", async () => {
		vi.stubGlobal(
			"fetch",
			vi.fn(
				async (..._args: unknown[]) =>
					({
						ok: true,
						status: 200,
						text: async () => JSON.stringify(FIXTURE_USAGE),
					}) as unknown as Response,
			),
		);
		const res = await GET();
		expect(res.status).toBe(200);
		expect(await res.json()).toEqual(FIXTURE_USAGE);
	});

	it("calls the gateway EXACTLY ONCE per load (spec §2.5b)", async () => {
		const spy = vi.fn(
			async (..._args: unknown[]) =>
				({
					ok: true,
					status: 200,
					text: async () => JSON.stringify(FIXTURE_USAGE),
				}) as unknown as Response,
		);
		vi.stubGlobal("fetch", spy);
		await GET();
		expect(spy).toHaveBeenCalledTimes(1);
	});

	it("reads with the MINTED per-user gateway JWT, never the client header", async () => {
		const spy = vi.fn(
			async (..._args: unknown[]) =>
				({
					ok: true,
					status: 200,
					text: async () => JSON.stringify(FIXTURE_USAGE),
				}) as unknown as Response,
		);
		vi.stubGlobal("fetch", spy);
		await GET();
		const init = spy.mock.calls[0]?.[1] as
			| { headers?: Record<string, string> }
			| undefined;
		expect(init?.headers?.authorization).toBe("Bearer minted-jwt");
	});
});
