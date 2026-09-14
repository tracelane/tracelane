/**
 * format — ONE formatter per metric kind (DSH-11 §3 / §3d).
 *
 * The inventory found five cost formatters, two zero-duration glyphs and a
 * `0.0%` beside a `0%` on adjacent surfaces. Every one collapses into these. A
 * page never formats a metric itself; it asks for the kind it is showing.
 *
 * The small-sample rule lives here because it IS a formatting rule: precision the
 * sample cannot support is not rendered. `98.571%` over 70 calls is a lie told
 * with decimals.
 */

import { fmtDurMs } from "@tracelanedev/ui";

export type MetricKind =
	| "count"
	| "tokens"
	| "percent"
	| "duration_ms"
	| "currency"
	| "ratio";

/** `1,284` — grouped integer. Non-finite → `—`. */
export function fmtCount(n: number | null | undefined): string {
	if (n == null || !Number.isFinite(n)) return "—";
	return Math.round(n).toLocaleString("en-US");
}

/** `1.2K` · `3.4M` — for tokens and other volumes where the magnitude is the point. */
export function fmtCompact(n: number | null | undefined): string {
	if (n == null || !Number.isFinite(n)) return "—";
	const a = Math.abs(n);
	if (a >= 1_000_000_000) return `${(n / 1_000_000_000).toFixed(1)}B`;
	if (a >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
	if (a >= 1_000) return `${(n / 1_000).toFixed(1)}K`;
	return String(Math.round(n));
}

/**
 * Duration in ms → the app's ONE duration formatter (`fmtDurMs`, adaptive µs/ms/s).
 * `null`, non-finite or a non-positive value is `—`: a latency of 0 ms is not a
 * measurement anywhere in this product, it is the absence of one.
 */
export function fmtDurationMs(ms: number | null | undefined): string {
	if (ms == null || !Number.isFinite(ms) || ms <= 0) return "—";
	return fmtDurMs(ms);
}

/**
 * USD. `null`/`undefined` (unpriced, unreachable) → `—`; a measured 0 → `$0.00`;
 * ≥ $1 → 2 dp; below → 4 dp so a fraction of a cent is visible.
 */
export function fmtUsd(usd: number | null | undefined): string {
	if (usd == null || !Number.isFinite(usd)) return "—";
	if (usd === 0) return "$0.00";
	if (Math.abs(usd) >= 1000) return `$${(usd / 1000).toFixed(1)}K`;
	if (Math.abs(usd) >= 1) return `$${usd.toFixed(2)}`;
	return `$${usd.toFixed(4)}`;
}

/** `1.25×` — burn-rate style multiple; `∞×` past a zero budget. */
export function fmtRatio(x: number | null | undefined): string {
	if (x == null || Number.isNaN(x)) return "—";
	return Number.isFinite(x) ? `${x.toFixed(2)}×` : "∞×";
}

/**
 * The smallest sample in which ONE failure is a legitimate breach of `target`:
 * `ceil(1 / (1 − target))` — 99.9 % → 1,000; 99 % → 100; 99.95 % → 2,000.
 * Rates with no target use the flat floor of 100.
 */
export const RATE_FLOOR = 100;
export function sampleFloor(target?: number | null): number {
	if (target == null || target >= 1 || target <= 0) return RATE_FLOOR;
	// Round before ceil: 1 / (1 − 0.9995) is 2000.0000000000005 in floating point,
	// and a floor of 2,001 would be a lie about the arithmetic, not the sample.
	return Math.max(
		RATE_FLOOR,
		Math.ceil(Math.round((1 / (1 - target)) * 1e6) / 1e6),
	);
}

/** Decimals a percentage may carry at sample size `n`: 1 below 1,000, 2 below 100,000, then 3. */
export function percentDecimals(n: number): number {
	if (!(n >= 1000)) return 1;
	return n < 100_000 ? 2 : 3;
}

export interface PercentOptions {
	/** The denominator — requests, verdicts, samples. */
	n?: number | null;
	/** Availability-style target (0–1); sets the floor. */
	target?: number | null;
	/** Override the floor outright. */
	floor?: number;
	/** Fixed decimals, ignoring the sample rule (for a gateway-computed value with no n). */
	decimals?: number;
}

export interface FormattedPercent {
	text: string;
	/** True when `n` is known and below the floor — tone must be neutral. */
	belowFloor: boolean;
	/** True when `n` is 0 — render the empty copy, never `0%` or `100%`. */
	noSample: boolean;
	floor: number;
	decimals: number;
}

/**
 * A percentage with the small-sample rule applied. The caller passes the RAW
 * value (0–100) and the sample; this decides the decimals and whether a target
 * comparison is even allowed.
 */
export function fmtPercent(
	value: number | null | undefined,
	opts: PercentOptions = {},
): FormattedPercent {
	const floor = opts.floor ?? sampleFloor(opts.target);
	const n = opts.n ?? null;
	if (n === 0) {
		return { text: "—", belowFloor: true, noSample: true, floor, decimals: 0 };
	}
	if (value == null || !Number.isFinite(value)) {
		return {
			text: "—",
			belowFloor: false,
			noSample: false,
			floor,
			decimals: 0,
		};
	}
	const belowFloor = n !== null && n < floor;
	const decimals =
		opts.decimals ?? (n === null ? 1 : belowFloor ? 1 : percentDecimals(n));
	return {
		text: `${value.toFixed(decimals)}%`,
		belowFloor,
		noSample: false,
		floor,
		decimals,
	};
}

/** `1 of 70` — the fraction shown beside a small-sample rate. */
export function fmtFraction(num: number, n: number): string {
	return `${fmtCount(num)} of ${fmtCount(n)}`;
}

/** Format by kind, for the chart tooltip and any generic renderer. */
export function fmtByKind(
	kind: MetricKind,
	v: number | null | undefined,
): string {
	switch (kind) {
		case "count":
			return fmtCount(v);
		case "tokens":
			return fmtCompact(v);
		case "percent":
			return fmtPercent(v, { decimals: 2 }).text;
		case "duration_ms":
			return fmtDurationMs(v);
		case "currency":
			return fmtUsd(v);
		case "ratio":
			return fmtRatio(v);
	}
}

/**
 * Error-budget remaining, as the /dashboard budget card and a custom-dashboard
 * `budget_remaining` stat tile both print it (B-341 — it lived in `app/dashboard/page.tsx`
 * alone, so a tile could only re-implement it, and a re-implementation is a divergence
 * waiting for a taste change).
 */
export function fmtBudget(pct: number): string {
	if (!Number.isFinite(pct)) return "over budget";
	if (pct < 0) return `${Math.abs(pct).toFixed(0)}% over`;
	return `${pct.toFixed(0)}%`;
}
