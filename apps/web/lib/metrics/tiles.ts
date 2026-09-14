/**
 * tiles — two things in one file:
 *
 * 1. `sloHeadline` — the headline SLO tiles, computed ONCE for every page that
 *    shows them (DSH-11 §3c). `/dashboard` and `/slo` both render LLM calls,
 *    Error rate, Availability and the burn arithmetic; each used to derive them
 *    from a different response and format them with its own rules. Now both call
 *    `sloHeadline` with the same inputs and get the same strings, and
 *    `consistency.test.ts` proves it.
 *
 * 2. `renderTile` / `fetchTileData` — DSH-13 custom dashboard tile rendering.
 *    Maps (metric_id, shape, dimension) → the SAME fetcher + formatter the
 *    built-in pages use, so a custom tile and its built-in counterpart always
 *    show the same string for the same window (spec §7.1 parity property).
 *    No new fetch layer — every call goes through `lib/metrics/fetch.ts`.
 */

import { type SloBudget, computeSloBudget } from "@/app/slo/budget";
import type { SloSummary } from "@/app/slo/types";

// `./fetch` reaches `@/lib/gateway` → `@/lib/auth` (the WorkOS runtime). It is loaded on FIRST
// USE, not at module top, so the pure exports of this file (`sloHeadline`) stay importable from
// a plain vitest environment — `consistency.test.ts` broke at module load when this was a
// top-level import (2026-09-05). `vi.mock("./fetch")` still applies to a dynamic import.
type Fetchers = typeof import("./fetch");
let fetchersPromise: Promise<Fetchers> | null = null;
const F = (): Promise<Fetchers> => {
	fetchersPromise ??= import("./fetch");
	return fetchersPromise;
};
import {
	type FormattedPercent,
	fmtBudget,
	fmtCompact,
	fmtCount,
	fmtDurationMs,
	fmtPercent,
	fmtRatio,
	fmtUsd,
} from "./format";
import { METRICS, type MetricId } from "./registry";
import { sloLatencySeries, sloTrafficSeries } from "./series";
import {
	DEFAULT_SLO_TARGET,
	type Limiter,
	shapeSupported,
} from "./tile-support";
import type { TimeRange } from "./time-range";

export interface SloHeadlineInput {
	/** `GET /v1/slo/summary` — null when that route was unreachable. */
	summary: SloSummary | null;
	/** Fallback totals from the per-row response, LLM rows only (provider ≠ ''). */
	fallback: { requests: number; errors: number };
	/** The plan's availability target, 0–1. */
	target: number;
	/** True when the whole SLO family was unreachable — every tile is `—`. */
	unreachable: boolean;
}

export interface SloHeadline {
	requests: number;
	errors: number;
	/** True when the totals came from the per-row fallback, not the summary. */
	fromFallback: boolean;
	budget: SloBudget;
	llmCalls: string;
	errorRate: FormattedPercent;
	availability: FormattedPercent;
	/** `n` the rates were measured over (the LLM-request count). */
	n: number | null;
}

export function sloHeadline(input: SloHeadlineInput): SloHeadline {
	const requests = input.summary?.requests ?? input.fallback.requests;
	const errors = input.summary?.errors ?? input.fallback.errors;
	const budget = computeSloBudget(requests, errors, input.target);
	const n = input.unreachable ? null : requests;
	return {
		requests,
		errors,
		fromFallback: !input.summary,
		budget,
		n,
		llmCalls: input.unreachable ? "—" : fmtCount(requests),
		errorRate: fmtPercent(budget.errorRatePct, { n, floor: 100 }),
		availability: fmtPercent(budget.availabilityPct, {
			n,
			target: input.target,
		}),
	};
}

// ── DSH-13 renderTile support ─────────────────────────────────────────────────

/**
 * The shape of a tile stored in Postgres (dashboard_tiles row).
 * Mirrors `DashboardTile` from schema.ts — kept separate so this file has no
 * Drizzle dependency (it is used in both RSC and client contexts).
 */
export interface TileDef {
	id: string;
	metricId: string;
	shape: "stat" | "series" | "breakdown";
	dimension?: string | null;
	filterDimension?: string | null;
	filterValue?: string | null;
	title?: string;
}

/**
 * Result of `fetchTileData` — the raw data the tile needs to render.
 * `kind` narrows the union so the rendering layer never needs to know which
 * fetcher was called.
 */
export type TileData =
	| { kind: "stat"; value: string; n: number | null }
	| { kind: "series"; data: import("./series").ChartData; label: string }
	| { kind: "breakdown"; rows: BreakdownRow[]; label: string }
	| { kind: "unreachable"; label: string }
	| { kind: "unknown_metric"; metricId: string }
	| { kind: "entitlement_blocked"; label: string }
	| { kind: "unsupported_shape"; reason: string };

export type BreakdownRow = {
	key: string;
	value: number;
	n?: number;
};

type Win = Pick<TimeRange, "sinceMs" | "untilMs" | "bucketMs">;

/**
 * Fetch the data for a single tile.
 *
 * The parity invariant (spec §7.1): for a `stat` tile, `value` equals the string
 * the built-in page's StatCard shows for the same metric and window. Every fetch
 * goes through the same fetcher in `lib/metrics/fetch.ts`; every format goes
 * through the same `fmtByKind` / `fmtPercent` the built-in pages call.
 *
 * NOTE: `fetchTileData` is called from a server component — it may use async/await
 * freely. The call site (`TileContainer`) wraps each tile in its own Suspense
 * boundary so a slow tile does not block the others.
 */
export interface TileFetchOptions {
	/** The plan's availability target (0–1) — the same value `/dashboard` measures against. */
	target?: number;
	/** Bounds concurrent tile fetches for one page render (spec §3: 8). */
	run?: Limiter;
}

export async function fetchTileData(
	tile: TileDef,
	range: Win,
	opts: TileFetchOptions = {},
): Promise<TileData> {
	const run: Limiter = opts.run ?? ((f) => f());
	return run(() => fetchTileDataInner(tile, range, opts));
}

async function fetchTileDataInner(
	tile: TileDef,
	range: Win,
	opts: TileFetchOptions,
): Promise<TileData> {
	const metricId = tile.metricId as MetricId;
	if (!(metricId in METRICS)) {
		return { kind: "unknown_metric", metricId: tile.metricId };
	}
	const def = METRICS[metricId];
	const label = def.label;
	const shape = tile.shape;

	// The closed matrix, checked BEFORE any fetch: a shape this metric does not support is
	// said so, never rendered as "—" or "unreachable" (verifier, 2026-09-05).
	if (!shapeSupported(metricId, shape, tile.dimension)) {
		return {
			kind: "unsupported_shape",
			reason:
				shape === "breakdown"
					? `${label} has no breakdown by ${tile.dimension ?? "(none)"}`
					: `${label} cannot be shown as a ${shape} tile`,
		};
	}

	// ── stat shape ─────────────────────────────────────────────────────────────
	if (shape === "stat") {
		const v = await fetchStatValue(metricId, range, opts);
		if (v === null) return { kind: "unreachable", label };
		return { kind: "stat", value: v.formatted, n: v.n };
	}

	// ── series shape ───────────────────────────────────────────────────────────
	if (shape === "series") {
		const data = await fetchSeriesData(metricId, range);
		if (data === null) return { kind: "unreachable", label };
		return { kind: "series", data, label };
	}

	// ── breakdown shape ────────────────────────────────────────────────────────
	if (shape === "breakdown") {
		const dimension = tile.dimension;
		if (!dimension) {
			return {
				kind: "unsupported_shape",
				reason: "breakdown requires a dimension",
			};
		}
		const rows = await fetchBreakdownData(metricId, dimension, range);
		if (rows === null) return { kind: "unreachable", label };
		if (rows === "unsupported") {
			return {
				kind: "unsupported_shape",
				reason: `${label} has no breakdown by ${dimension}`,
			};
		}
		return { kind: "breakdown", rows, label };
	}

	return { kind: "unsupported_shape", reason: `unknown shape: ${shape}` };
}

// ── Internal: stat value fetch ────────────────────────────────────────────────

interface StatValue {
	formatted: string;
	n: number | null;
}

/**
 * B-341: the SLO-family stat tiles compute through the SAME `sloHeadline` the built-in
 * `/dashboard` and `/slo` pages call, with the SAME inputs — the summary route, the per-row
 * LLM totals as the fallback when the summary is unreachable, and the plan's target. A tile
 * that reached for `fetchSloSummary` alone printed nothing where the page printed a fallback
 * total, and used the default floor where the page used the plan's.
 */
async function sloHeadFor(
	r: Win,
	opts: TileFetchOptions,
): Promise<SloHeadline | null> {
	const f = await F();
	const [summary, rows] = await Promise.all([
		f.fetchSloSummary(r),
		f.fetchSloRows(r),
	]);
	if (summary === null && rows === null) return null;
	const llm = (rows ?? []).filter((x) => x.provider !== "");
	return sloHeadline({
		summary,
		fallback: {
			requests: llm.reduce((acc, x) => acc + x.requests, 0),
			errors: llm.reduce((acc, x) => acc + x.errors, 0),
		},
		target: opts.target ?? DEFAULT_SLO_TARGET,
		unreachable: false,
	});
}

async function fetchStatValue(
	id: MetricId,
	r: Win,
	opts: TileFetchOptions = {},
): Promise<StatValue | null> {
	const def = METRICS[id];

	switch (id) {
		// SLO family — all read from slo/summary or slo/models
		case "llm_calls": {
			const head = await sloHeadFor(r, opts);
			if (head === null) return null;
			return { formatted: head.llmCalls, n: head.n };
		}
		case "error_rate": {
			const head = await sloHeadFor(r, opts);
			if (head === null) return null;
			return { formatted: head.errorRate.text, n: head.n };
		}
		case "availability": {
			const head = await sloHeadFor(r, opts);
			if (head === null) return null;
			return { formatted: head.availability.text, n: head.n };
		}
		case "burn_rate": {
			const head = await sloHeadFor(r, opts);
			if (head === null) return null;
			// `fmtRatio` is what /dashboard's error-budget card renders (`const fmtBurn = fmtRatio`).
			return { formatted: fmtRatio(head.budget.burnRate), n: head.n };
		}
		case "budget_remaining": {
			const head = await sloHeadFor(r, opts);
			if (head === null) return null;
			return {
				formatted: fmtBudget(head.budget.budgetRemainingPct),
				n: head.n,
			};
		}
		case "tokens": {
			const models = await (await F()).fetchSloModels(r);
			if (models === null) return null;
			const total = models.reduce(
				(acc, m) => acc + m.total_input_tokens + m.total_output_tokens,
				0,
			);
			return { formatted: fmtCompact(total), n: models.length };
		}
		case "tokens_input": {
			const models = await (await F()).fetchSloModels(r);
			if (models === null) return null;
			const total = models.reduce((acc, m) => acc + m.total_input_tokens, 0);
			return { formatted: fmtCompact(total), n: models.length };
		}
		case "tokens_output": {
			const models = await (await F()).fetchSloModels(r);
			if (models === null) return null;
			const total = models.reduce((acc, m) => acc + m.total_output_tokens, 0);
			return { formatted: fmtCompact(total), n: models.length };
		}
		case "latency_p50": {
			const s = await (await F()).fetchSloSummary(r);
			if (s === null) return null;
			return { formatted: fmtDurationMs(s.p50_ms), n: s.requests };
		}
		case "latency_p95": {
			const s = await (await F()).fetchSloSummary(r);
			if (s === null) return null;
			return { formatted: fmtDurationMs(s.p95_ms), n: s.requests };
		}
		case "latency_p99": {
			const s = await (await F()).fetchSloSummary(r);
			if (s === null) return null;
			return { formatted: fmtDurationMs(s.p99_ms), n: s.requests };
		}
		case "spend_est": {
			// The built-in spend card reads `/v1/gateway/stats` and prints "—" for null OR a
			// measured zero (nothing priced); a different fetcher printed "$0.00" (B-341).
			const gw = await (await F()).fetchGatewayStatsFor(r);
			if (gw === null) return null;
			const spend = gw.total_cost_usd;
			return {
				formatted: spend === null || spend === 0 ? "—" : fmtUsd(spend),
				n: gw.total_requests,
			};
		}
		case "requests_routed": {
			const gs = await (await F()).fetchGatewayStatsFor(r);
			if (gs === null) return null;
			return { formatted: fmtCount(gs.total_requests), n: gs.total_requests };
		}
		case "failed_routed": {
			const gs = await (await F()).fetchGatewayStatsFor(r);
			if (gs === null) return null;
			const failed = gs.total_errors;
			return { formatted: fmtCount(failed), n: gs.total_requests };
		}
		case "cache_hit_rate": {
			const gs = await (await F()).fetchGatewayStatsFor(r);
			if (gs === null) return null;
			return {
				formatted: fmtPercent(gs.cache_hit_rate_pct, {
					n: gs.total_requests,
					floor: 100,
				}).text,
				n: gs.total_requests,
			};
		}
		case "overhead_p95": {
			const lb = await (await F()).fetchLatencyBreakdownFor(r);
			if (lb === null) return null;
			return { formatted: fmtDurationMs(lb.overhead_p95_ms), n: null };
		}
		case "provider_p95": {
			const lb = await (await F()).fetchLatencyBreakdownFor(r);
			if (lb === null) return null;
			return { formatted: fmtDurationMs(lb.provider_p95_ms), n: null };
		}
		case "ttft_p95": {
			const lb = await (await F()).fetchLatencyBreakdownFor(r);
			if (lb === null) return null;
			return { formatted: fmtDurationMs(lb.ttft_p95_ms), n: null };
		}
		case "verdicts": {
			const gs = await (await F()).fetchGuardrailStatsFor(r);
			if (gs === null) return null;
			return {
				formatted: fmtCount(gs.total_evaluations),
				n: gs.total_evaluations,
			};
		}
		case "block_rate": {
			const gs = await (await F()).fetchGuardrailStatsFor(r);
			if (gs === null) return null;
			return {
				formatted: fmtPercent(gs.block_rate_pct, {
					n: gs.total_evaluations,
					floor: 100,
				}).text,
				n: gs.total_evaluations,
			};
		}
		case "fail_open_rate": {
			const gs = await (await F()).fetchGuardrailStatsFor(r);
			if (gs === null) return null;
			return {
				formatted: fmtPercent(gs.fail_open_rate_pct, {
					n: gs.total_evaluations,
					floor: 100,
				}).text,
				n: gs.total_evaluations,
			};
		}
		case "guardrail_overhead_p95": {
			const gs = await (await F()).fetchGuardrailStatsFor(r);
			if (gs === null) return null;
			return { formatted: fmtDurationMs(gs.p95_ms), n: gs.total_evaluations };
		}
		case "signatures_matched": {
			const sig = await (await F()).fetchSignaturesFor(r);
			if (sig === null) return null;
			return {
				formatted: fmtCount(sig.signatures.length),
				n: sig.signatures.length,
			};
		}
		case "traces_affected": {
			const sig = await (await F()).fetchSignaturesFor(r);
			if (sig === null) return null;
			return {
				formatted:
					sig.total_traces_affected !== null
						? fmtCount(sig.total_traces_affected)
						: "—",
				n: sig.total_traces_affected,
			};
		}
		case "traces_total": {
			const total = await (await F()).fetchTraceCountFor(
				r,
				new URLSearchParams(),
			);
			if (total === null) return null;
			return { formatted: fmtCount(total), n: total };
		}
		case "sessions_listed": {
			const sessions = await (await F()).fetchSessionsFor(r);
			if (sessions === null) return null;
			return { formatted: fmtCount(sessions.length), n: sessions.length };
		}
		case "tool_calls": {
			const tools = await (await F()).fetchToolAnalyticsFor(r);
			if (tools === null) return null;
			return { formatted: fmtCount(tools.total_calls), n: tools.total_calls };
		}
		// Process-level metrics — these are instant/lifetime, stat only makes sense
		// but the gateway does return them through /v1/gateway/stats.
		case "providers_active": {
			const gs = await (await F()).fetchGatewayStatsFor(r);
			if (gs === null) return null;
			return { formatted: fmtCount(gs.provider_count), n: null };
		}
		case "failovers": {
			const gs = await (await F()).fetchGatewayStatsFor(r);
			if (gs === null) return null;
			return { formatted: fmtCount(gs.total_failovers), n: null };
		}
		case "rate_limited_since_start": {
			const gs = await (await F()).fetchGatewayStatsFor(r);
			if (gs === null) return null;
			return { formatted: fmtCount(gs.rate_limited_since_start), n: null };
		}
		case "budget_exceeded_since_start": {
			const gs = await (await F()).fetchGatewayStatsFor(r);
			if (gs === null) return null;
			return { formatted: fmtCount(gs.budget_exceeded_since_start), n: null };
		}
		case "open_breakers": {
			const gs = await (await F()).fetchGatewayStatsFor(r);
			if (gs === null) return null;
			return { formatted: fmtCount(gs.open_breakers), n: null };
		}
		// Derived / computed metrics — not directly available as a single fetch
		case "slo_target":
		case "unpriced_requests":
		case "traffic_by_model":
		case "decision_mix":
		case "traffic_series":
		case "errors_series":
		case "latency_series":
			// These are series or summary metrics; `stat` shape not meaningful —
			// fall through to the unsupported path.
			return {
				formatted: "—",
				n: null,
			};
		default: {
			const _exhaustive: never = id;
			return null;
		}
	}
}

// ── Internal: series data fetch ───────────────────────────────────────────────

async function fetchSeriesData(
	id: MetricId,
	r: Win,
): Promise<import("./series").ChartData | null> {
	switch (id) {
		case "traffic_series":
		case "llm_calls":
		case "error_rate":
		case "tokens":
		case "errors_series": {
			const rows = await (await F()).fetchSloRows(r);
			if (rows === null) return null;
			return sloTrafficSeries(r, rows);
		}
		case "latency_series":
		case "latency_p50":
		case "latency_p95":
		case "latency_p99": {
			const points = await (await F()).fetchSloTimeseries(r);
			if (points === null) return null;
			return sloLatencySeries(r, points);
		}
		default:
			// Most metrics have no natural series representation — return a
			// placeholder so the tile renders "unsupported shape" rather than crashing.
			return null;
	}
}

// ── Internal: breakdown data fetch ───────────────────────────────────────────

/** Registry id → the gateway's `BreakdownMetric` name (`crates/gateway/src/trace_reads.rs`). */
const BREAKDOWN_METRIC: Partial<Record<MetricId, string>> = {
	llm_calls: "requests",
	requests_routed: "requests",
	failed_routed: "errors",
	error_rate: "error_rate",
	latency_p50: "p50_ms",
	latency_p95: "p95_ms",
	tokens_input: "input_tokens",
	tokens_output: "output_tokens",
	spend_est: "cost_usd",
};

/** Tile dimension → the gateway's `BreakdownBy` name. `decision` / `rail` are served by the
 *  guardrail path above and have no generic breakdown. */
const BREAKDOWN_BY: Record<string, string | undefined> = {
	model: "model",
	provider: "provider",
	api_key: "key",
	key: "key",
	status: "status",
	operation: "operation",
};

async function fetchBreakdownData(
	id: MetricId,
	dimension: string,
	r: Win,
): Promise<BreakdownRow[] | null | "unsupported"> {
	const { gatewayGet, GatewayError } = await import("@/lib/gateway");
	const { windowParams: wp } = await import("./time-range");

	// Well-served pairs — use existing routes.
	if (id === "spend_est") {
		const byMap: Record<
			string,
			import("@/lib/gateway-ops").CostBreakdown["by"]
		> = {
			model: "model",
			provider: "provider",
			api_key: "key",
		};
		const by = byMap[dimension];
		if (by) {
			const cost = await (await F()).fetchCostBreakdownFor(r, by);
			if (cost === null) return null;
			return (cost.rows ?? []).map((row) => ({
				key: row.dimension || "(unattributed)",
				value: row.cost_usd ?? 0,
				n: row.requests,
			}));
		}
	}

	if (id === "verdicts" || id === "block_rate" || id === "decision_mix") {
		// Guardrail verdicts can be broken down by decision or rail.
		const verdicts = await (await F()).fetchGuardrailVerdictsFor(r, {
			limit: 200,
		});
		if (verdicts === null) return null;
		// Aggregate by decision or by first rail parsed from the JSON string.
		const agg = new Map<string, number>();
		for (const v of verdicts) {
			let key = "unknown";
			if (dimension === "decision") {
				key = v.decision || "unknown";
			} else if (dimension === "rail") {
				try {
					const parsed = JSON.parse(v.rails) as Array<{ rail?: string }>;
					key = parsed[0]?.rail ?? "unknown";
				} catch {
					key = "unknown";
				}
			}
			agg.set(key, (agg.get(key) ?? 0) + 1);
		}
		return [...agg.entries()]
			.sort((a, b) => b[1] - a[1])
			.map(([key, value]) => ({ key, value, n: value }));
	}

	if (id === "traces_total" || id === "requests_routed" || id === "llm_calls") {
		// Groups via /v1/traces/groups?by=
		const dimMap: Record<string, string> = {
			model: "model",
			provider: "provider",
			status: "status",
			operation: "operation",
		};
		const by = dimMap[dimension];
		if (by) {
			const q = wp(r);
			q.set("by", by);
			q.set("limit", "20");
			try {
				const data = await gatewayGet<{
					groups: { key: string; count: number }[];
				}>(`/v1/traces/groups?${q.toString()}`);
				return (data.groups ?? []).map((g) => ({
					key: g.key ?? "(unknown)",
					value: g.count,
					n: g.count,
				}));
			} catch (err) {
				if (err instanceof GatewayError) return null;
				throw err;
			}
		}
	}

	// Fallback: `GET /v1/metrics/breakdown` — the gateway's closed (metric, by) enums, which
	// are NOT registry ids. A registry metric with no entry here has no breakdown by these
	// dimensions; the tile says so instead of rendering an empty table as "no rows".
	const gatewayMetric = BREAKDOWN_METRIC[id];
	const gatewayBy = BREAKDOWN_BY[dimension];
	if (!gatewayMetric || !gatewayBy) return "unsupported";
	const q = wp(r);
	q.set("metric", gatewayMetric);
	q.set("by", gatewayBy);
	q.set("limit", "20");
	try {
		const data = await gatewayGet<{
			metric: string;
			by: string;
			rows: { key: string; value: number; n: number }[];
			window: { since: string; until: string; clamped: boolean };
		}>(`/v1/metrics/breakdown?${q.toString()}`);
		return (data.rows ?? []).map((row) => ({
			key: row.key,
			value: row.value,
			n: row.n,
		}));
	} catch (err) {
		if (err instanceof GatewayError) {
			// The coordinator route may not be deployed yet — degrade gracefully.
			return null;
		}
		throw err;
	}
}
