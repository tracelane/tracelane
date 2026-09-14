/**
 * fetch — the ONE gateway read layer for windowed metrics (DSH-11 §2).
 *
 * Every function takes the page's `TimeRange` and asks the gateway for exactly
 * that window through `windowParams` — `since` + `until` as RFC3339, never
 * `hours=`. A rolling preset expressed as two instants is what lets the tiles,
 * the chart and every drill-through agree to the millisecond, and it is the only
 * form a custom window can take.
 *
 * Every read goes through `gatewayGet`, which forwards the user's token and binds
 * no tenant id: the gateway resolves org → internal tenant UUID (ADR-042). This
 * file never sees `session.tenantId`.
 *
 * `null` means UNREACHABLE (a `GatewayError`), which the registry's zero-vs-unknown
 * rule renders as `—` plus the warming banner — never as `0`. Anything else (the
 * auth redirect) propagates. A reachable-but-empty window comes back as real data
 * with zero counts, and that difference is the whole point.
 *
 * `scripts/ci/check-page-fanout.py` counts calls to these by name — add a new
 * fetcher to its `GATEWAY_CALLS` list, or a page's WAN round trips go uncounted.
 */

import type {
	SloModelRow,
	SloRow,
	SloSummary,
	SloTimePoint,
} from "@/app/slo/types";
import { GatewayError, gatewayGet } from "@/lib/gateway";
import type { CostBreakdown, GatewayStats } from "@/lib/gateway-ops";
import type { GuardrailStats, GuardrailVerdict } from "@/lib/guardrails";
import type { LatencyBreakdown } from "@/lib/latency";
import type { SessionSummary } from "@/lib/sessions";
import { type TimeRange, windowParams } from "./time-range";

type Win = Pick<TimeRange, "sinceMs" | "untilMs" | "bucketMs">;

async function orNull<T>(p: Promise<T>): Promise<T | null> {
	try {
		return await p;
	} catch (err) {
		if (err instanceof GatewayError) return null;
		throw err;
	}
}

function url(path: string, q: URLSearchParams): string {
	const s = q.toString();
	return s ? `${path}?${s}` : path;
}

/**
 * The legacy `hours=` a route that has not yet learned `since/until` still reads.
 * Sent BESIDE the pair, never instead of it: a gateway that understands the pair
 * ignores `hours`, and one that does not gets the closest rolling window. The
 * spec's serialization point (gateway before web) is what keeps a custom window
 * honest; this is the fallback for the routes that only ever took hours.
 */
function hoursOf(r: Win): number {
	return Math.max(1, Math.ceil((r.untilMs - r.sinceMs) / 3_600_000));
}

// ── SLO family ────────────────────────────────────────────────────────────────

/** `GET /v1/slo` — per (bucket, provider, model) rows at the window's bucket. */
export function fetchSloRows(
	r: Win,
	opts: { provider?: string; model?: string } = {},
): Promise<SloRow[] | null> {
	const q = windowParams(r, { bucket: true });
	if (opts.provider) q.set("provider", opts.provider);
	if (opts.model) q.set("model", opts.model);
	return orNull(gatewayGet<SloRow[]>(url("/v1/slo", q)));
}

/** `GET /v1/slo/summary` — the TRUE window-wide quantiles + requests/errors. */
export function fetchSloSummary(
	r: Win,
	opts: { provider?: string; model?: string } = {},
): Promise<SloSummary | null> {
	const q = windowParams(r);
	if (opts.provider) q.set("provider", opts.provider);
	if (opts.model) q.set("model", opts.model);
	return orNull(gatewayGet<SloSummary>(url("/v1/slo/summary", q)));
}

/** `GET /v1/slo/models` — one merged row per (provider, model). */
export function fetchSloModels(r: Win): Promise<SloModelRow[] | null> {
	return orNull(
		gatewayGet<SloModelRow[]>(url("/v1/slo/models", windowParams(r))),
	);
}

/** `GET /v1/slo/timeseries` — one merged row per bucket (p50/p95/p99, requests, errors). */
export function fetchSloTimeseries(
	r: Win,
	opts: { provider?: string; model?: string } = {},
): Promise<SloTimePoint[] | null> {
	const q = windowParams(r, { bucket: true });
	if (opts.provider) q.set("provider", opts.provider);
	if (opts.model) q.set("model", opts.model);
	return orNull(gatewayGet<SloTimePoint[]>(url("/v1/slo/timeseries", q)));
}

// ── spans family ──────────────────────────────────────────────────────────────

/** `GET /v1/gateway/stats` — router health over spans FINAL. */
export function fetchGatewayStatsFor(r: Win): Promise<GatewayStats | null> {
	return orNull(
		gatewayGet<GatewayStats>(url("/v1/gateway/stats", windowParams(r))),
	);
}

/**
 * `GET /v1/costs` — spend attribution. Takes `hours` beside the pair (see `hoursOf`).
 * `scope` is OPTIONAL and omitted by default — the gateway's own `CostQuery.scope`
 * defaults to `"all"` (`crates/gateway/src/trace_reads.rs::CostScope::parse`), so
 * every existing caller that never passed one keeps asking for exactly what it
 * asked for before this parameter existed (Tara's `cost_breakdown` tool is the
 * first caller that needs to narrow to `production`/`eval`).
 */
export function fetchCostBreakdownFor(
	r: Win,
	by: CostBreakdown["by"],
	scope?: CostBreakdown["scope"],
): Promise<CostBreakdown | null> {
	const q = windowParams(r);
	q.set("hours", String(hoursOf(r)));
	q.set("by", by);
	if (scope) q.set("scope", scope);
	return orNull(gatewayGet<CostBreakdown>(url("/v1/costs", q)));
}

/** `GET /v1/query/latency-breakdown` — gateway overhead vs provider vs TTFT. */
export function fetchLatencyBreakdownFor(
	r: Win,
): Promise<LatencyBreakdown | null> {
	const q = windowParams(r);
	q.set("hours", String(hoursOf(r)));
	return orNull(
		gatewayGet<LatencyBreakdown>(url("/v1/query/latency-breakdown", q)),
	);
}

/** One tool row from `/v1/query/tool-analytics`. */
export type ToolRow = {
	tool: string;
	calls: number;
	errors: number;
	p95_ms: number;
};
export type ToolAnalytics = {
	window_hours: number;
	total_calls: number;
	tools: ToolRow[];
};

/** `GET /v1/query/tool-analytics` — B-232: no writer produces the key yet. */
export function fetchToolAnalyticsFor(r: Win): Promise<ToolAnalytics | null> {
	const q = windowParams(r);
	q.set("hours", String(hoursOf(r)));
	return orNull(gatewayGet<ToolAnalytics>(url("/v1/query/tool-analytics", q)));
}

// ── guardrails ────────────────────────────────────────────────────────────────

/** `GET /v1/guardrails/stats`. */
export function fetchGuardrailStatsFor(r: Win): Promise<GuardrailStats | null> {
	const q = windowParams(r);
	q.set("hours", String(hoursOf(r)));
	return orNull(gatewayGet<GuardrailStats>(url("/v1/guardrails/stats", q)));
}

/** `GET /v1/guardrails/verdicts` — the decision-mix click-through. */
export function fetchGuardrailVerdictsFor(
	r: Win,
	opts: {
		decision?: string;
		correlationId?: string;
		/** B-335a: one rail's verdicts (`R4_trifecta`); the gateway filters inside the `rails` JSON. */
		rail?: string;
		limit?: number;
	} = {},
): Promise<GuardrailVerdict[] | null> {
	const q = windowParams(r);
	q.set("hours", String(hoursOf(r)));
	if (opts.decision) q.set("decision", opts.decision);
	if (opts.correlationId) q.set("correlation_id", opts.correlationId);
	if (opts.rail) q.set("rail", opts.rail);
	if (opts.limit !== undefined) q.set("limit", String(opts.limit));
	return orNull(
		gatewayGet<{ verdicts: GuardrailVerdict[] }>(
			url("/v1/guardrails/verdicts", q),
		).then((x) => x.verdicts),
	);
}

// ── signatures ────────────────────────────────────────────────────────────────

export type SignatureHitRow = {
	signature_id: string;
	your_hits: number;
	traces_affected: number;
	action: "blocking" | "flag-only";
	/** RFC3339 — always present (`formatDateTime(min(start_time))` in the SQL). */
	first_seen: string;
	last_seen: string;
};

/** `GET /v1/query/signatures` — live AFT-1 hits; `liveIds` scopes the distinct total. */
export function fetchSignaturesFor(
	r: Win,
	liveIds: readonly string[] = [],
): Promise<{
	signatures: SignatureHitRow[];
	total_traces_affected: number | null;
} | null> {
	const q = windowParams(r);
	if (liveIds.length > 0) q.set("live_ids", liveIds.join(","));
	return orNull(
		gatewayGet<{
			signatures: SignatureHitRow[];
			total_traces_affected?: number;
		}>(url("/v1/query/signatures", q)).then((d) => ({
			signatures: d.signatures,
			// `undefined` is UNKNOWN, not zero — the old page's `?? 0` was B-334.
			total_traces_affected:
				typeof d.total_traces_affected === "number"
					? d.total_traces_affected
					: null,
		})),
	);
}

// ── traces / sessions ─────────────────────────────────────────────────────────

/**
 * `GET /v1/traces/count` — `filters` are the list's own params (model, status, q…).
 * `r` is `null` for the list's explicit "all time" mode, the one windowed read
 * that legitimately has no window.
 */
export function fetchTraceCountFor(
	r: Win | null,
	filters: URLSearchParams,
): Promise<number | null> {
	const q = new URLSearchParams(filters);
	if (r) for (const [k, v] of windowParams(r)) q.set(k, v);
	q.delete("limit");
	q.delete("cursor");
	return orNull(
		gatewayGet<{ total: number }>(url("/v1/traces/count", q)).then((c) =>
			typeof c.total === "number" ? c.total : null,
		),
	);
}

/** `GET /v1/sessions` — the list window plus its sort/filter params. */
export function fetchSessionsFor(
	r: Win,
	opts: {
		sort?: string;
		order?: string;
		status?: string;
		model?: string;
		limit?: number;
	} = {},
): Promise<SessionSummary[] | null> {
	const q = windowParams(r);
	if (opts.sort) q.set("sort", opts.sort);
	if (opts.order) q.set("order", opts.order);
	if (opts.status) q.set("status", opts.status);
	if (opts.model) q.set("model", opts.model);
	if (opts.limit !== undefined) q.set("limit", String(opts.limit));
	return orNull(
		gatewayGet<{ sessions: SessionSummary[] }>(url("/v1/sessions", q)).then(
			(d) => d.sessions,
		),
	);
}
