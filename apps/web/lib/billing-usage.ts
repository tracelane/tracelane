/**
 * Shared types + pure formatters for the `/settings/billing` usage board
 * (spec `BILL-01-metering-and-tiers.md` §2.6, §3, §8).
 *
 * `GatewayUsageResponse` is the PINNED CONTRACT for the real
 * `GET /v1/billing/usage` (`crates/gateway/src/billing/usage.rs:110-181`,
 * slice B1 + B2's `warn_pct`/`ceiling_reached`/`rates` additions) — copied
 * field-for-field, not approximated. A shape drift there is a compile error
 * here, never a silent `any`.
 *
 * Percentages and badges are computed CLIENT-SIDE from `used`/`included`
 * (never sent pre-computed by the gateway) — spec §3 "derived client-side
 * from the two numbers above".
 */

export interface MeterBlock {
	used: number | null;
	/** `null` = custom (Enterprise) — never rendered as a percentage or bar. */
	included: number | null;
	burst_exempt: number;
	overage_units: number;
	overage_usd: number | null;
	projection_month_end: number | null;
	/** Non-null once the daily job has computed this meter at least once. */
	last_computed_at: string | null;
	/** Display unit, server-provided: "GB", "GB·mo", or "" for a bare count. */
	unit: string;
}

/** One graduated rate band: `[lo, hi)`, `hi: null` = the open top band. */
export interface RateBand {
	lo: number;
	hi: number | null;
	usd_per_unit: number;
}

/** The six meter keys as `rates` and the gateway's own wire keys name them. */
export type MeterRateKey =
	| "ingest_gb"
	| "hot_gb_month"
	| "series"
	| "scan_units"
	| "cold_gb_month"
	| "eval_runs";

export interface GatewayUsageResponse {
	/** Calendar month this response covers, e.g. "2026-09". */
	month: string;
	/**
	 * B-410: the Polar billing cycle the figures are rated over, when the
	 * tenant has a paid subscription (ISO timestamps). Absent/null = the
	 * calendar month above. The invoice is Polar's; this makes the page agree with it.
	 */
	period_start?: string | null;
	period_end?: string | null;
	computed_at: string;
	/** False when the rate card itself could not be loaded — distinct from a meter simply having no data yet. */
	rates_available: boolean;
	rate_card_version: string;
	spend_ceiling_usd: number | null;
	overflow_mode: "auto_age" | "auto_overage";
	projected_overage_usd: number | null;
	/** True only when the ceiling has actually fired this month (AUTO-AGE acted). No day-count is provided — never fabricate one. */
	ceiling_reached: boolean;
	/**
	 * Non-null only when AUTO-AGE has shrunk the tenant's indexed window below
	 * `plan.indexed_window_days` — the window's CURRENT size in days, not a
	 * delta. `null` (including when absent — older gateway builds may omit the
	 * field entirely) means auto-age has not shrunk anything; the day count
	 * the ceiling banner shows is `plan.indexed_window_days -
	 * auto_age_window_days`, computed here, never sent pre-computed.
	 */
	auto_age_window_days?: number | null;
	/** `billing_policy.warning_thresholds_pct`, passed through — never a literal on our side. */
	warn_pct: [number, number];
	meters: {
		ingest: MeterBlock;
		hot: MeterBlock;
		series: MeterBlock;
		query: MeterBlock;
		cold: MeterBlock;
		evals: MeterBlock;
	};
	plan: {
		lookup_key: string;
		price_monthly_usd: number | null;
		price_annual_month_usd: number | null;
		price_from_usd: number | null;
		indexed_window_days: number;
		queryable_days: number;
		ledger_days: number;
		unlimited_seats: boolean;
		f_sso: boolean;
	};
	rates: Record<MeterRateKey, RateBand[]>;
}

/** The UI's six tile keys, in display order, mapped to the wire's `meters`/`rates` keys. */
export const METER_KEYS = [
	"ingest",
	"hot",
	"series",
	"query",
	"cold",
	"evals",
] as const;
export type MeterKey = (typeof METER_KEYS)[number];

export const METER_TO_RATE_KEY: Record<MeterKey, MeterRateKey> = {
	ingest: "ingest_gb",
	hot: "hot_gb_month",
	series: "series",
	query: "scan_units",
	cold: "cold_gb_month",
	evals: "eval_runs",
};

function meterBlocks(resp: GatewayUsageResponse): MeterBlock[] {
	return METER_KEYS.map((k) => resp.meters[k]);
}

/** The worst (highest) used/included percentage among allowance-bearing meters. `0` if none apply. */
export function worstMeterPct(resp: GatewayUsageResponse): number {
	let worst = 0;
	for (const m of meterBlocks(resp)) {
		if (m.used === null || m.included === null || m.included <= 0) continue;
		const pct = (m.used / m.included) * 100;
		if (pct > worst) worst = pct;
	}
	return worst;
}

/**
 * The number of days AUTO-AGE has moved out of the indexed window, for the
 * ceiling-resolved banner's honest copy — `plan.indexed_window_days -
 * auto_age_window_days`, both real gateway numbers. `undefined` (never a
 * fabricated `0`) whenever `auto_age_window_days` is `null` or absent, i.e.
 * auto-age has not actually shrunk the window yet.
 */
export function agedOutDays(resp: GatewayUsageResponse): number | undefined {
	if (typeof resp.auto_age_window_days !== "number") return undefined;
	return resp.plan.indexed_window_days - resp.auto_age_window_days;
}

/**
 * The current-band rate for a meter, from the gateway's own graduated
 * `rates` bands — replaces guessing at "the lowest band" client-side. Picks
 * the band whose `[lo, hi)` contains `referenceValue`; falls back to the
 * first band if none matches (e.g. `referenceValue` is 0 and every band
 * starts above it) and to `null` if the meter has no bands at all.
 */
export function currentBandRate(
	bands: RateBand[] | undefined,
	referenceValue: number,
): RateBand | null {
	if (!bands || bands.length === 0) return null;
	const hit = bands.find(
		(b) => referenceValue >= b.lo && (b.hi === null || referenceValue < b.hi),
	);
	return hit ?? bands[0] ?? null;
}

/** meter unit -> the "/<unit>" suffix used in a rate string ("$16.00/GB·mo"). */
const RATE_UNIT_SUFFIX: Record<MeterRateKey, string> = {
	ingest_gb: "/GB",
	hot_gb_month: "/GB·mo",
	series: "/series-mo",
	scan_units: "/scan-unit",
	cold_gb_month: "/GB-mo",
	eval_runs: "/run",
};

/**
 * A display-only rate string for the warning banner ("Overage $64.00 at
 * $16.00/GB·mo"), read from the gateway's own `rates` bands at the meter's
 * current (or projected) usage — never a client-side guess.
 */
export function meterRateText(
	key: MeterKey,
	resp: GatewayUsageResponse,
): string | null {
	const rateKey = METER_TO_RATE_KEY[key];
	const block = resp.meters[key];
	const reference = block.projection_month_end ?? block.used ?? 0;
	const band = currentBandRate(resp.rates?.[rateKey], reference);
	if (!band) return null;
	return `$${band.usd_per_unit.toFixed(band.usd_per_unit < 1 ? 3 : 2)}${RATE_UNIT_SUFFIX[rateKey]}`;
}

export interface WindowBreakdownRow {
	label: string;
	gb: number;
	pct: number;
}
export interface GatewayWindowBreakdownResponse {
	by: "project" | "service" | "capture" | "shape";
	rows: WindowBreakdownRow[];
	shown: number;
	total: number;
}

export type WarnLevel = "ok" | "warn" | "danger";

/** used/included ≥ 90% → danger, ≥ 75% → warn, else ok. `included: null` → ok (no allowance to compare against). */
export function warnLevel(
	used: number | null,
	included: number | null,
	thresholds: [number, number] = [75, 90],
): WarnLevel {
	if (used === null || included === null || included <= 0) return "ok";
	const pct = (used / included) * 100;
	if (pct >= thresholds[1]) return "danger";
	if (pct >= thresholds[0]) return "warn";
	return "ok";
}

/** Capped at 999% for display (spec §3). `null` when there is nothing to divide by. */
export function pctOf(
	used: number | null,
	included: number | null,
): number | null {
	if (used === null || included === null || included <= 0) return null;
	return Math.min(999, Math.round((used / included) * 100));
}

/**
 * The seven spec §4 states, derived CLIENT-SIDE from the gateway response —
 * the gateway sends no `state` field. Order is the precedence: the first
 * matching rule wins.
 *
 *  1. `error`        — the fetch failed, or there is no response at all.
 *  2. `empty`         — every meter's `used` is `0` or `null`, AND the rate
 *                        card loaded (`rates_available`) — so this is a
 *                        genuinely quiet tenant, not a metering outage
 *                        wearing an empty costume.
 *  3. `not_entitled`  — `plan.lookup_key === "free_v1"`. Checked AFTER
 *                        `empty` so a brand-new Free workspace still reads as
 *                        "no usage yet", not as "Free's no-overage variant".
 *  4. `partial`       — a genuine MIX: at least one meter has `used === null`
 *                        while at least one other has a real value (the
 *                        daily job is behind on some meters, not down
 *                        entirely — spec §4 "a meter tile reads '—'", the
 *                        OTHER tiles keep rendering).
 *  5. otherwise       — `ok` / `warn` / `danger` from the worst
 *                        allowance-bearing meter against `warn_pct`.
 *
 * Per-tile "this ONE meter has no data yet" rendering does not depend on
 * this function — `UsageBoard` checks each `MeterBlock.used === null`
 * independently, because a `partial` OVERALL state must not hide the fact
 * that a DIFFERENT meter is genuinely over its warning threshold.
 */
export function deriveUsageState(
	resp: GatewayUsageResponse | null,
	httpOk: boolean,
): UsageState {
	if (!httpOk || resp === null) return "error";

	const blocks = meterBlocks(resp);
	const allZeroOrNull = blocks.every((m) => m.used === null || m.used === 0);
	if (allZeroOrNull && resp.rates_available) return "empty";

	if (resp.plan.lookup_key === "free_v1") return "not_entitled";

	const anyNull = blocks.some((m) => m.used === null);
	const anySet = blocks.some((m) => m.used !== null);
	if (anyNull && anySet) return "partial";

	const worst = worstMeterPct(resp);
	const [warnAt, dangerAt] = resp.warn_pct;
	if (worst >= dangerAt) return "danger";
	if (worst >= warnAt) return "warn";
	return "ok";
}

export type UsageState =
	| "ok"
	| "warn"
	| "danger"
	| "empty"
	| "error"
	| "partial"
	| "not_entitled";

/** `1234.5` -> "1.2K"; small numbers pass through with locale grouping. */
export function formatCompactCount(n: number): string {
	if (n >= 1_000_000) {
		const m = n / 1_000_000;
		return `${Number.isInteger(m) ? m : m.toFixed(1)}M`;
	}
	if (n >= 1_000) {
		const k = n / 1_000;
		return `${Number.isInteger(k) ? k : k.toFixed(1)}K`;
	}
	return n.toLocaleString("en-US");
}

/**
 * GB/GB-month tile values: whole numbers for anything ≥10 ("182", "300" — the
 * wireframe's Team/Business tiles), up to 2 trimmed decimals below that
 * ("0.2", "0.09", "0.25" — the wireframe's Free variant). A flat
 * `toFixed(0)` would round Free's sub-1 numbers to "0", producing captions
 * like "0 / 1 GB" beside a correctly-computed "20%" — a real defect this
 * fixes (found rendering the Free-tier state, not merely written to spec).
 */
export function formatGbAdaptive(n: number): string {
	if (n >= 10) return String(Math.round(n));
	return String(Math.round(n * 100) / 100);
}

/** `0.9` -> "0.9 GB"; `1500` -> "1.5 TB". */
export function formatGbUnit(gb: number): string {
	if (gb >= 1000) return `${(gb / 1000).toFixed(1)} TB`;
	if (gb >= 10) return `${gb.toFixed(1)} GB`;
	return `${gb.toFixed(2)} GB`;
}

/**
 * The wireframe's review note: keep the value AND its unit on one caption
 * line so it never wraps mid-figure ("182 / 300" stranded from "GB" reads as
 * a layout bug). Every meter renders through this one function so the rule
 * cannot regress per-tile. `unit` is the gateway's own `MeterBlock.unit`.
 */
export function formatMeterCaption(opts: {
	used: number | null;
	included: number | null;
	unit: string;
	usedFormat: (n: number) => string;
}): string {
	const { used, included, unit, usedFormat } = opts;
	if (used === null) return "—";
	const usedText = usedFormat(used);
	if (included === null) return unit ? `${usedText} ${unit}` : usedText; // custom/no denominator
	const includedText = usedFormat(included);
	return unit
		? `${usedText} / ${includedText} ${unit}`
		: `${usedText} / ${includedText}`;
}
