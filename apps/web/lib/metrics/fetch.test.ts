/**
 * Tests for lib/metrics/fetch — the ONE gateway read layer for windowed metrics.
 *
 * B-500 (2026-09-21): the four SLO routes must be asked for the SAME window in
 * the SAME granularity. `fetchSloRows` and `fetchSloTimeseries` sent the
 * sub-hour bucket and so read `spans FINAL` bounded by `start_time`;
 * `fetchSloSummary` and `fetchSloModels` did not, and so read `slo_hourly_stats`
 * bounded by `bucket_hour = toStartOfHour(start_time)` — the headline and the
 * chart counted different traffic under one label on every window ≤ 24 h.
 *
 * `gatewayGet` is a spy: the assertion is on the URL the layer ASKS for, which
 * is the whole contract of this file.
 */

import { beforeEach, describe, expect, it, vi } from "vitest";

const { gatewayGetSpy } = vi.hoisted(() => ({
	gatewayGetSpy: vi.fn(async (_path: string): Promise<unknown> => []),
}));

vi.mock("@/lib/gateway", () => ({
	gatewayGet: (path: string) => gatewayGetSpy(path),
	GatewayError: class GatewayError extends Error {
		status: number;
		constructor(status: number, message: string) {
			super(message);
			this.status = status;
		}
	},
}));

import {
	fetchSloModels,
	fetchSloRows,
	fetchSloSummary,
	fetchSloTimeseries,
} from "./fetch";

const MIN = 60_000;
const HOUR = 3_600_000;
const UNTIL = Date.parse("2026-09-21T14:37:12.000Z");

function askedFor(): URL {
	expect(gatewayGetSpy).toHaveBeenCalledTimes(1);
	const path = gatewayGetSpy.mock.calls[0]?.[0];
	expect(typeof path).toBe("string");
	return new URL(path as string, "http://gateway.invalid");
}

beforeEach(() => {
	gatewayGetSpy.mockClear();
});

describe("fetch — the SLO family asks every route for one window at one granularity", () => {
	// The 6h preset: a 5-minute bucket, well inside the sub-hour rule (§3a.4).
	const subHour = {
		sinceMs: UNTIL - 6 * HOUR,
		untilMs: UNTIL,
		bucketMs: 5 * MIN,
	};

	it.each([
		["fetchSloRows", "/v1/slo", () => fetchSloRows(subHour)],
		["fetchSloSummary", "/v1/slo/summary", () => fetchSloSummary(subHour)],
		["fetchSloModels", "/v1/slo/models", () => fetchSloModels(subHour)],
		[
			"fetchSloTimeseries",
			"/v1/slo/timeseries",
			() => fetchSloTimeseries(subHour),
		],
	] as const)(
		"%s sends bucket_minutes=5 beside since/until on %s",
		async (_name, route, call) => {
			await call();
			const u = askedFor();
			expect(u.pathname).toBe(route);
			expect(u.searchParams.get("since")).toBe("2026-09-21T08:37:12.000Z");
			expect(u.searchParams.get("until")).toBe("2026-09-21T14:37:12.000Z");
			expect(u.searchParams.get("bucket_minutes")).toBe("5");
			expect(u.searchParams.get("bucket")).toBeNull();
			expect(u.searchParams.get("hours")).toBeNull();
		},
	);

	it("an hour-or-wider bucket is sent as `bucket` (hours) to the summary and the table too", async () => {
		const threeDays = {
			sinceMs: UNTIL - 72 * HOUR,
			untilMs: UNTIL,
			bucketMs: HOUR,
		};
		await fetchSloSummary(threeDays);
		expect(askedFor().searchParams.get("bucket")).toBe("1");
		gatewayGetSpy.mockClear();
		await fetchSloModels(threeDays);
		const u = askedFor();
		expect(u.searchParams.get("bucket")).toBe("1");
		expect(u.searchParams.get("bucket_minutes")).toBeNull();
	});

	it("provider / model filters ride beside the window on the summary", async () => {
		await fetchSloSummary(subHour, { provider: "openai", model: "gpt-4o" });
		const u = askedFor();
		expect(u.searchParams.get("provider")).toBe("openai");
		expect(u.searchParams.get("model")).toBe("gpt-4o");
		expect(u.searchParams.get("bucket_minutes")).toBe("5");
	});
});
