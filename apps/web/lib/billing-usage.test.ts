/**
 * Pure formatter + state-derivation tests for the usage board (spec `BILL-01`
 * §2.6, §3, §4, §5). `GatewayUsageResponse` here is the PINNED gateway
 * contract (`crates/gateway/src/billing/usage.rs:110-181` + B2's
 * `warn_pct`/`ceiling_reached`/`rates`) — every fixture below is shaped
 * exactly like the real wire body, never an approximation.
 * Negative cases first per `.claude/rules/testing.md`.
 */

import { describe, expect, it } from "vitest";
import {
	type GatewayUsageResponse,
	type MeterBlock,
	agedOutDays,
	currentBandRate,
	deriveUsageState,
	formatCompactCount,
	formatGbAdaptive,
	formatGbUnit,
	formatMeterCaption,
	meterRateText,
	pctOf,
	warnLevel,
	worstMeterPct,
} from "./billing-usage";

function block(overrides: Partial<MeterBlock> = {}): MeterBlock {
	return {
		used: 0,
		included: 100,
		burst_exempt: 0,
		overage_units: 0,
		overage_usd: null,
		projection_month_end: 0,
		last_computed_at: "2026-09-13T04:00:00Z",
		unit: "",
		...overrides,
	};
}

/** A full, wire-shaped response. Every test overrides only what it needs. */
function usageFixture(
	overrides: {
		meters?: Partial<GatewayUsageResponse["meters"]>;
		plan?: Partial<GatewayUsageResponse["plan"]>;
		rates_available?: boolean;
		warn_pct?: [number, number];
		rates?: Partial<GatewayUsageResponse["rates"]>;
		auto_age_window_days?: number | null;
	} = {},
): GatewayUsageResponse {
	const emptyBands = {
		ingest_gb: [],
		hot_gb_month: [],
		series: [],
		scan_units: [],
		cold_gb_month: [],
		eval_runs: [],
	};
	return {
		month: "2026-09",
		computed_at: "2026-09-13T04:00:00Z",
		rates_available: overrides.rates_available ?? true,
		rate_card_version: "v3",
		spend_ceiling_usd: null,
		overflow_mode: "auto_age",
		projected_overage_usd: null,
		ceiling_reached: false,
		auto_age_window_days: overrides.auto_age_window_days ?? null,
		warn_pct: overrides.warn_pct ?? [75, 90],
		meters: {
			ingest: block(),
			hot: block(),
			series: block(),
			query: block(),
			cold: block({ included: null }),
			evals: block(),
			...overrides.meters,
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
			...overrides.plan,
		},
		rates: { ...emptyBands, ...overrides.rates },
	};
}

describe("deriveUsageState — the seven spec §4 states, in precedence order", () => {
	it("error: the fetch failed (httpOk=false), regardless of any response body", () => {
		expect(deriveUsageState(usageFixture(), false)).toBe("error");
	});

	it("error: there is no response at all", () => {
		expect(deriveUsageState(null, true)).toBe("error");
	});

	it("empty: every meter's used is 0 or null AND the rate card loaded", () => {
		const resp = usageFixture({
			meters: {
				ingest: block({ used: 0 }),
				hot: block({ used: null }),
				series: block({ used: 0 }),
				query: block({ used: 0 }),
				cold: block({ used: 0, included: null }),
				evals: block({ used: null }),
			},
		});
		expect(deriveUsageState(resp, true)).toBe("empty");
	});

	it("NOT empty when rates_available is false, even if every meter reads zero", () => {
		const resp = usageFixture({ rates_available: false });
		expect(deriveUsageState(resp, true)).not.toBe("empty");
	});

	it("not_entitled: Free plan with real usage (checked AFTER empty)", () => {
		const resp = usageFixture({
			plan: { lookup_key: "free_v1" },
			meters: { ingest: block({ used: 0.2, included: 1 }) },
		});
		expect(deriveUsageState(resp, true)).toBe("not_entitled");
	});

	it("a brand-new Free workspace (all zero) reads empty, not not_entitled", () => {
		const resp = usageFixture({ plan: { lookup_key: "free_v1" } });
		expect(deriveUsageState(resp, true)).toBe("empty");
	});

	it("partial: a genuine MIX — one meter has no data yet, others do", () => {
		const resp = usageFixture({
			meters: {
				ingest: block({ used: 182, included: 300 }),
				hot: block({ used: null, included: 75, last_computed_at: null }),
			},
		});
		expect(deriveUsageState(resp, true)).toBe("partial");
	});

	it("ok: every meter well under its warning threshold", () => {
		const resp = usageFixture({
			meters: { ingest: block({ used: 42, included: 300 }) },
		});
		expect(deriveUsageState(resp, true)).toBe("ok");
	});

	it("warn: the worst meter is at/above warn_pct[0] but below warn_pct[1]", () => {
		const resp = usageFixture({
			meters: { hot: block({ used: 61, included: 75 }) }, // 81%
		});
		expect(deriveUsageState(resp, true)).toBe("warn");
	});

	it("danger: the worst meter is at/above warn_pct[1]", () => {
		const resp = usageFixture({
			meters: { hot: block({ used: 69, included: 75 }) }, // 92%
		});
		expect(deriveUsageState(resp, true)).toBe("danger");
	});

	it("honours a custom warn_pct pair from the response, never a literal on our side", () => {
		const resp = usageFixture({
			warn_pct: [40, 80],
			meters: { ingest: block({ used: 50, included: 100 }) }, // 50%
		});
		expect(deriveUsageState(resp, true)).toBe("warn");
	});
});

describe("worstMeterPct", () => {
	it("ignores meters with no allowance to compare against (Enterprise custom)", () => {
		const resp = usageFixture({
			meters: { cold: block({ used: 500, included: null }) },
		});
		expect(worstMeterPct(resp)).toBe(0);
	});
	it("picks the highest percentage among allowance-bearing meters", () => {
		const resp = usageFixture({
			meters: {
				ingest: block({ used: 50, included: 100 }), // 50%
				hot: block({ used: 90, included: 100 }), // 90%
			},
		});
		expect(worstMeterPct(resp)).toBe(90);
	});
});

describe("currentBandRate — the graduated ladder, read from the gateway's own bands", () => {
	const bands = [
		{ lo: 0, hi: 500, usd_per_unit: 16 },
		{ lo: 500, hi: 2000, usd_per_unit: 8 },
		{ lo: 2000, hi: 10000, usd_per_unit: 4.5 },
		{ lo: 10000, hi: null, usd_per_unit: 3 },
	];
	it("no bands at all -> null", () => {
		expect(currentBandRate([], 100)).toBeNull();
		expect(currentBandRate(undefined, 100)).toBeNull();
	});
	it("picks the band the reference value falls inside", () => {
		expect(currentBandRate(bands, 42)?.usd_per_unit).toBe(16);
		expect(currentBandRate(bands, 600)?.usd_per_unit).toBe(8);
		expect(currentBandRate(bands, 3000)?.usd_per_unit).toBe(4.5);
	});
	it("the open top band (hi: null) matches anything at or above its lo", () => {
		expect(currentBandRate(bands, 50000)?.usd_per_unit).toBe(3);
	});
	it("falls back to the first band when the value is below every lo", () => {
		expect(currentBandRate(bands, -1)?.usd_per_unit).toBe(16);
	});
});

describe("meterRateText — reads the gateway's rates, never a client-side guess", () => {
	it("null when the meter has no bands", () => {
		const resp = usageFixture();
		expect(meterRateText("hot", resp)).toBeNull();
	});
	it("uses the band at the meter's PROJECTED usage, formatted with its unit suffix", () => {
		const resp = usageFixture({
			meters: {
				hot: block({ used: 61, included: 75, projection_month_end: 79 }),
			},
			rates: {
				hot_gb_month: [
					{ lo: 0, hi: 500, usd_per_unit: 16 },
					{ lo: 500, hi: null, usd_per_unit: 8 },
				],
			},
		});
		expect(meterRateText("hot", resp)).toBe("$16.00/GB·mo");
	});
	it("sub-$1 rates render three decimals (series/evals precision)", () => {
		const resp = usageFixture({
			meters: { evals: block({ used: 12400, projection_month_end: 18000 }) },
			rates: { eval_runs: [{ lo: 0, hi: null, usd_per_unit: 0.005 }] },
		});
		expect(meterRateText("evals", resp)).toBe("$0.005/run");
	});
});

describe("agedOutDays — the ceiling banner's day count, never fabricated", () => {
	it("undefined when auto-age has not shrunk anything (null), even with a ceiling reached; a number ONLY when the gateway reports a real shrunk window", () => {
		const notShrunk = usageFixture({ auto_age_window_days: null });
		expect(agedOutDays(notShrunk)).toBeUndefined();

		const shrunk = usageFixture({
			plan: { indexed_window_days: 90 },
			auto_age_window_days: 76,
		});
		expect(agedOutDays(shrunk)).toBe(14);
	});
});

describe("warnLevel", () => {
	it("no included allowance (Enterprise custom) is never a warning", () => {
		expect(warnLevel(1000, null)).toBe("ok");
	});
	it("no used data yet is never a warning", () => {
		expect(warnLevel(null, 100)).toBe("ok");
	});
	it("below 75% is ok", () => {
		expect(warnLevel(60, 100)).toBe("ok");
	});
	it("75-89% is warn", () => {
		expect(warnLevel(75, 100)).toBe("warn");
		expect(warnLevel(89, 100)).toBe("warn");
	});
	it("90%+ is danger", () => {
		expect(warnLevel(90, 100)).toBe("danger");
		expect(warnLevel(250, 100)).toBe("danger");
	});
	it("honours a custom threshold pair (billing_policy, never a literal on our side)", () => {
		expect(warnLevel(50, 100, [40, 80])).toBe("warn");
	});
});

describe("pctOf", () => {
	it("null when there is nothing to divide by", () => {
		expect(pctOf(10, null)).toBeNull();
		expect(pctOf(null, 100)).toBeNull();
		expect(pctOf(10, 0)).toBeNull();
	});
	it("caps at 999% for display (spec §3)", () => {
		expect(pctOf(5000, 100)).toBe(999);
	});
	it("rounds to the nearest percent", () => {
		expect(pctOf(61, 75)).toBe(81);
	});
});

describe("formatCompactCount", () => {
	it("small counts use locale grouping, not K/M suffixes", () => {
		expect(formatCompactCount(4)).toBe("4");
		expect(formatCompactCount(1310)).toBe("1.3K");
	});
	it("compacts thousands and millions", () => {
		expect(formatCompactCount(9100)).toBe("9.1K");
		expect(formatCompactCount(12400)).toBe("12.4K");
		expect(formatCompactCount(1_000_000)).toBe("1M");
	});
});

describe("formatGbAdaptive — the Free-tier caption bug this fixes", () => {
	it("keeps decimals below 10 so a small value never rounds to 0", () => {
		// Found rendering the Free-tier state: 0.2 GB used / 1 GB included at
		// toFixed(0) read as "0 / 1 GB" beside a correctly-computed "20%".
		expect(formatGbAdaptive(0.2)).toBe("0.2");
		expect(formatGbAdaptive(0.09)).toBe("0.09");
		expect(formatGbAdaptive(0.25)).toBe("0.25");
	});
	it("rounds to a whole number at 10 and above, matching the wireframe's Team/Business tiles", () => {
		expect(formatGbAdaptive(182)).toBe("182");
		expect(formatGbAdaptive(300)).toBe("300");
		expect(formatGbAdaptive(61)).toBe("61");
	});
});

describe("formatGbUnit", () => {
	it("sub-GB values keep two decimals", () => {
		expect(formatGbUnit(0.9)).toBe("0.90 GB");
	});
	it("switches to TB at 1000 GB", () => {
		expect(formatGbUnit(1500)).toBe("1.5 TB");
	});
});

describe("formatMeterCaption — the wireframe's 'unit never wraps' review note", () => {
	it("unknown usage renders an em dash, not a broken fraction", () => {
		expect(
			formatMeterCaption({
				used: null,
				included: 300,
				unit: "GB",
				usedFormat: String,
			}),
		).toBe("—");
	});
	it("custom/no-denominator (Enterprise) renders used + unit only", () => {
		expect(
			formatMeterCaption({
				used: 42,
				included: null,
				unit: "GB",
				usedFormat: String,
			}),
		).toBe("42 GB");
	});
	it("an empty unit (count-based meters) never leaves a trailing space", () => {
		expect(
			formatMeterCaption({
				used: 9100,
				included: 15000,
				unit: "",
				usedFormat: String,
			}),
		).toBe("9100 / 15000");
	});
	it("keeps the value and unit as ONE string — the wireframe review note", () => {
		const caption = formatMeterCaption({
			used: 182,
			included: 300,
			unit: "GB",
			usedFormat: String,
		});
		expect(caption).toBe("182 / 300 GB");
		// The unit is the LAST token, never split from the numbers by anything
		// that could become an independent flex/wrap child.
		expect(caption.endsWith(" GB")).toBe(true);
	});
});
