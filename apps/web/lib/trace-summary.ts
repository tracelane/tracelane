/**
 * trace-summary — trace-level rollups + waterfall geometry, derived purely from
 * the real span set. Every field is summed from stored attributes; nothing is
 * synthesized. A metric with no source span stays `undefined` (never a
 * fabricated `0`), matching the `extractGenAi` cost/token contract in
 * `trace-tree.ts`.
 *
 * Pure and deterministic — no DOM, no clock, no network (testable in node).
 */

import type { Span } from "@/components/trace-viewer/types";
import { extractGenAi } from "@/lib/trace-tree";

/** Trace-level rollup. Optional fields are absent when no span reported them. */
export interface TraceSummary {
	spanCount: number;
	errorCount: number;
	/** Spans the guardrail layer warned (1) or blocked (2) on. */
	interventionCount: number;
	startTimeUs: number;
	endTimeUs: number;
	/** Wall-clock span of the trace (max end − min start), microseconds. */
	totalDurationUs: number;
	inputTokens?: number;
	outputTokens?: number;
	totalTokens?: number;
	/** Sum of the real stored per-span `gen_ai_usage_cost`; absent if none priced. */
	cost?: number;
	/** Distinct resolved models, in first-seen order. */
	models: string[];
	/** Distinct resolved providers, in first-seen order. */
	providers: string[];
	/**
	 * OBS-20: distinct end-user ids across the trace, in first-seen order.
	 *
	 * An ARRAY rather than a single value, for the same reason `models` is one:
	 * a trace can legitimately carry more than one span, and asserting a single
	 * end user would silently pick whichever span happened to be first. In
	 * practice a gateway-proxied trace is one span and this has 0 or 1 entries.
	 */
	endUsers: string[];
}

/** Start of a span in microseconds — precise column first, ISO fallback. */
export function spanStartUs(s: Span): number {
	if (typeof s.start_time_us === "number" && Number.isFinite(s.start_time_us)) {
		return s.start_time_us;
	}
	const ms = Date.parse(s.start_time);
	return Number.isFinite(ms) ? ms * 1000 : 0;
}

/**
 * A span's bar geometry as a percentage of the trace window — the ONE formula
 * both {@link WaterfallView} and `SwimlaneView` (OBS-49) resolve their bars
 * against, so "render parity" between the two views is a property of sharing
 * this function rather than something asserted after the fact on two separate
 * implementations that could drift.
 *
 * `leftPct` is clamped to 0 (a span starting before the window, which should
 * not happen but must never render off-screen). `widthPct` has a 0.5% floor so
 * a near-zero-duration span is still visible, and is capped so a bar never
 * overruns the right edge of the track.
 */
export function barGeometry(
	span: Span,
	startUs: number,
	totalUs: number,
): { leftPct: number; widthPct: number } {
	const offsetUs = Math.max(0, spanStartUs(span) - startUs);
	const leftPct = totalUs > 0 ? (offsetUs / totalUs) * 100 : 0;
	const rawWidth = totalUs > 0 ? (span.duration_us / totalUs) * 100 : 100;
	const widthPct = Math.min(Math.max(rawWidth, 0.5), 100 - leftPct);
	return { leftPct, widthPct };
}

/** [min start, max end] of the span set in microseconds (end = start + duration). */
export function traceTimeBounds(spans: Span[]): {
	startUs: number;
	endUs: number;
} {
	let startUs = Number.POSITIVE_INFINITY;
	let endUs = Number.NEGATIVE_INFINITY;
	for (const s of spans) {
		const st = spanStartUs(s);
		const en = st + Math.max(0, s.duration_us);
		if (st < startUs) startUs = st;
		if (en > endUs) endUs = en;
	}
	if (!Number.isFinite(startUs)) return { startUs: 0, endUs: 0 };
	return { startUs, endUs };
}

/**
 * Roll the span set up to a trace summary. Token/cost totals accumulate ONLY
 * from spans that actually reported them (a `seen` flag distinguishes "summed to
 * zero" from "no data" so an unpriced trace shows "—", not "$0.00").
 */
export function computeTraceSummary(spans: Span[]): TraceSummary {
	const { startUs, endUs } = traceTimeBounds(spans);

	let errorCount = 0;
	let interventionCount = 0;
	let inSum = 0;
	let inSeen = false;
	let outSum = 0;
	let outSeen = false;
	let totSum = 0;
	let totSeen = false;
	let costSum = 0;
	let costSeen = false;
	const models: string[] = [];
	const providers: string[] = [];
	const endUsers: string[] = [];

	for (const s of spans) {
		if (s.status_code === 2) errorCount++;
		if (s.intervention > 0) interventionCount++;
		const g = extractGenAi(s.attributes);
		if (g.inputTokens !== undefined) {
			inSum += g.inputTokens;
			inSeen = true;
		}
		if (g.outputTokens !== undefined) {
			outSum += g.outputTokens;
			outSeen = true;
		}
		if (g.totalTokens !== undefined) {
			totSum += g.totalTokens;
			totSeen = true;
		}
		if (g.cost !== undefined) {
			costSum += g.cost;
			costSeen = true;
		}
		if (g.model && !models.includes(g.model)) models.push(g.model);
		if (g.system && !providers.includes(g.system)) providers.push(g.system);
		if (g.endUser && !endUsers.includes(g.endUser)) endUsers.push(g.endUser);
	}

	return {
		spanCount: spans.length,
		errorCount,
		interventionCount,
		startTimeUs: startUs,
		endTimeUs: endUs,
		totalDurationUs: Math.max(0, endUs - startUs),
		inputTokens: inSeen ? inSum : undefined,
		outputTokens: outSeen ? outSum : undefined,
		totalTokens: totSeen ? totSum : undefined,
		cost: costSeen ? costSum : undefined,
		models,
		providers,
		endUsers,
	};
}
