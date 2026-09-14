/**
 * Which tile SHAPES and breakdown DIMENSIONS a registry metric supports — the closed
 * matrix DSH-13 composes from. PURE: no fetchers, no server imports, so the client-side
 * picker (`AddTileDialog`), the API validation and `fetchTileData` all read ONE source.
 *
 * WHY (verifier, 2026-09-05): the first build's picker listed 13 ids that do not exist in
 * the registry (every click a 422), a `stat` tile on a series-only metric rendered "—"
 * with no explanation, and `verdicts` by `provider` aggregated every row to "unknown".
 * All three were the same missing fact: not every metric supports every shape.
 *
 * `STAT_IDS` / `SERIES_IDS` mirror the `case` labels of `fetchStatValue` /
 * `fetchSeriesData` in `tiles.ts`; `dsh13.test.ts` re-derives both sets from that source
 * and fails if this file drifts from it.
 */
import { METRICS, type MetricId } from "./registry";

/**
 * The documented default availability target, 0.999 — the literal in
 * `apps/web/app/slo/budget.ts` (`SLO_TARGET_AVAILABILITY`). Restated here because a lib
 * module must not import from `app/`: under vitest, any import that resolves into the
 * Next `app/` tree is transformed as a server component and pulls the auth runtime, which
 * broke `lib/metrics/consistency.test.ts` at module load on 2026-09-05. `dsh13.test.ts`
 * reads `budget.ts` as TEXT and fails if the two literals ever differ.
 */
export const DEFAULT_SLO_TARGET = 0.999;

export const TILE_DIMENSIONS = [
	"model",
	"provider",
	"api_key",
	"status",
	"operation",
	"decision",
	"rail",
] as const;
export type TileDimension = (typeof TILE_DIMENSIONS)[number];

export const STAT_IDS: ReadonlySet<string> = new Set([
	"budget_remaining",
	"llm_calls",
	"error_rate",
	"availability",
	"burn_rate",
	"tokens",
	"tokens_input",
	"tokens_output",
	"latency_p50",
	"latency_p95",
	"latency_p99",
	"spend_est",
	"requests_routed",
	"failed_routed",
	"cache_hit_rate",
	"overhead_p95",
	"provider_p95",
	"ttft_p95",
	"verdicts",
	"block_rate",
	"fail_open_rate",
	"guardrail_overhead_p95",
	"signatures_matched",
	"traces_affected",
	"traces_total",
	"sessions_listed",
	"tool_calls",
	"providers_active",
	"failovers",
	"rate_limited_since_start",
	"budget_exceeded_since_start",
	"open_breakers",
]);

export const SERIES_IDS: ReadonlySet<string> = new Set([
	"traffic_series",
	"llm_calls",
	"error_rate",
	"tokens",
	"errors_series",
	"latency_series",
	"latency_p50",
	"latency_p95",
	"latency_p99",
]);

/** Registry ids the generic gateway route (`GET /v1/metrics/breakdown`) can break down. */
export const GENERIC_BREAKDOWN_IDS: ReadonlySet<string> = new Set([
	"llm_calls",
	"requests_routed",
	"failed_routed",
	"error_rate",
	"latency_p50",
	"latency_p95",
	"tokens_input",
	"tokens_output",
	"spend_est",
]);
const GENERIC_DIMS: readonly TileDimension[] = [
	"model",
	"provider",
	"api_key",
	"status",
	"operation",
];

export interface TileSupport {
	readonly stat: boolean;
	readonly series: boolean;
	readonly breakdownDimensions: readonly TileDimension[];
}

export function tileSupport(metricId: string): TileSupport {
	if (!(metricId in METRICS))
		return { stat: false, series: false, breakdownDimensions: [] };
	const id = metricId as MetricId;
	const dims = new Set<TileDimension>();
	if (id === "spend_est")
		for (const d of ["model", "provider", "api_key"] as const) dims.add(d);
	if (id === "verdicts" || id === "block_rate" || id === "decision_mix")
		for (const d of ["decision", "rail"] as const) dims.add(d);
	if (id === "traces_total" || id === "requests_routed" || id === "llm_calls")
		for (const d of ["model", "operation", "status"] as const) dims.add(d);
	if (GENERIC_BREAKDOWN_IDS.has(id)) for (const d of GENERIC_DIMS) dims.add(d);
	return {
		stat: STAT_IDS.has(id),
		series: SERIES_IDS.has(id),
		breakdownDimensions: TILE_DIMENSIONS.filter((d) => dims.has(d)),
	};
}

export function shapeSupported(
	metricId: string,
	shape: string,
	dimension?: string | null,
): boolean {
	const sup = tileSupport(metricId);
	if (shape === "stat") return sup.stat;
	if (shape === "series") return sup.series;
	if (shape === "breakdown")
		return (
			!!dimension &&
			sup.breakdownDimensions.includes(dimension as TileDimension)
		);
	return false;
}

/** A tiny async semaphore — bounds how many tiles fetch at once (spec §3: 8). */
export type Limiter = <T>(f: () => Promise<T>) => Promise<T>;
export function makeLimiter(max: number): Limiter {
	let active = 0;
	const queue: Array<() => void> = [];
	const next = () => {
		active -= 1;
		const w = queue.shift();
		if (w) w();
	};
	return async <T>(f: () => Promise<T>): Promise<T> => {
		if (active >= max)
			await new Promise<void>((resolve) => queue.push(resolve));
		active += 1;
		try {
			return await f();
		} finally {
			next();
		}
	};
}

// ── Tile sizing (2026-09-07) — spec §"Tile sizing" ──────────────────────────────
//
// Founder report: "I tried adding a tile and it was so slim that the graph wasn't
// visible at all." Root cause: `page.tsx` built the grid width as the TEMPLATE
// class `col-span-${tile.width}`. Tailwind only emits classes it can see LITERALLY
// in source — `col-span-4` / `col-span-6` never appear anywhere in the tree as a
// literal string (confirmed by grepping the built stylesheet: only `.col-span-12`
// is generated, because it is the one width used as a literal string elsewhere in
// this same file), so a width=4 or width=6 tile got NO grid-column rule at all and
// fell back to the CSS default `grid-column: auto` — one of twelve tracks, ~8% of
// the row, at ANY viewport. `WIDTH_CLASS` below is a static object literal so every
// class Tailwind must generate is visible to it at build time.
//
// The second half of the same bug: every series chart was hardcoded to
// `height={140}` regardless of the tile's width or the customer's intent — even a
// full-width (12-col) tile got a 140px sliver. `CHART_HEIGHT_PX` /
// `STAT_MIN_HEIGHT_PX` replace that fixed literal with a persisted, customer-
// chosen size (`dashboard_tiles.height`, migration 0037).

export const TILE_WIDTHS = [4, 6, 12] as const;
export type TileWidth = (typeof TILE_WIDTHS)[number];

export const TILE_HEIGHTS = ["compact", "regular", "tall"] as const;
export type TileHeight = (typeof TILE_HEIGHTS)[number];

/**
 * Grid column class per width — LITERAL strings only, never a template. Full
 * width below `md` (768px) so a 4- or 6-col tile is never sliced to a sliver on
 * a phone (a 4-col tile at 390px viewport width, if it rendered at all, would be
 * ~130px wide — unreadable for any chart).
 */
export const WIDTH_CLASS: Record<TileWidth, string> = {
	4: "col-span-12 md:col-span-4",
	6: "col-span-12 md:col-span-6",
	12: "col-span-12",
};

/** Chart plot height in px, by size. Never the old fixed 140px. */
export const CHART_HEIGHT_PX: Record<TileHeight, number> = {
	compact: 220,
	regular: 320,
	tall: 480,
};

/**
 * Minimum height in px for a `stat` tile, by size. Deliberately smaller than
 * `CHART_HEIGHT_PX` — a stat tile is a single number plus a sample line, not a
 * plot, so "tall" still leaves comfortable whitespace rather than an empty box.
 */
export const STAT_MIN_HEIGHT_PX: Record<TileHeight, number> = {
	compact: 132,
	regular: 168,
	tall: 208,
};

/**
 * LITERAL `min-h-[…]` classes mirroring `STAT_MIN_HEIGHT_PX` — a `StatCard`
 * takes `className`, not `style`, so this is passed straight through rather
 * than via an inline style. Static object, never a template: the same
 * discipline `WIDTH_CLASS` documents above, for the same reason.
 */
export const STAT_MIN_HEIGHT_CLASS: Record<TileHeight, string> = {
	compact: "min-h-[132px]",
	regular: "min-h-[168px]",
	tall: "min-h-[208px]",
};

/** The box height a tile of this shape+size renders at — the one function both
 * the server render (`page.tsx`) and the resize skeleton (`TileFrame`) call, so
 * they can never disagree about how tall "tall" is. */
export function heightPxFor(
	shape: "stat" | "series" | "breakdown",
	height: TileHeight,
): number {
	return shape === "stat"
		? STAT_MIN_HEIGHT_PX[height]
		: CHART_HEIGHT_PX[height];
}

/** Sensible per-shape defaults for the "Add tile" picker (spec §3d). */
export const SHAPE_SIZE_DEFAULTS: Record<
	"stat" | "series" | "breakdown",
	{ width: TileWidth; height: TileHeight }
> = {
	stat: { width: 4, height: "compact" },
	series: { width: 6, height: "regular" },
	breakdown: { width: 6, height: "regular" },
};

export function cycleWidth(
	current: TileWidth,
	dir: "narrower" | "wider",
): TileWidth {
	const idx = TILE_WIDTHS.indexOf(current);
	const nextIdx =
		dir === "wider"
			? Math.min(idx + 1, TILE_WIDTHS.length - 1)
			: Math.max(idx - 1, 0);
	return TILE_WIDTHS[nextIdx] as TileWidth;
}

export function cycleHeight(
	current: TileHeight,
	dir: "shorter" | "taller",
): TileHeight {
	const idx = TILE_HEIGHTS.indexOf(current);
	const nextIdx =
		dir === "taller"
			? Math.min(idx + 1, TILE_HEIGHTS.length - 1)
			: Math.max(idx - 1, 0);
	return TILE_HEIGHTS[nextIdx] as TileHeight;
}

// ── Section dividers (2026-09-07) — spec §9 ─────────────────────────────────
//
// Founder request, verbatim: "add divider on page so that when some metrics
// or tiles are added, they are aligned and of right shape and size." A
// divider is a fourth tile SHAPE: pure layout, no metric, no fetch, one fixed
// size. It is always `width = 12`, and because CSS Grid can only start a
// 12-wide item on a brand-new row, every tile placed after a divider is
// forced to column 1 of the next row — the existing `WIDTH_CLASS[12]` literal
// ("col-span-12") does the aligning; nothing new is needed in the grid itself.

/** The tile shape reserved for a full-width section header/rule. */
export const DIVIDER_SHAPE = "divider" as const;

/**
 * Reserved `metric_id` sentinel for a `shape: "divider"` tile. Deliberately
 * NOT a key in the METRICS registry (`registry.ts`) — a divider has no
 * metric, and a stray join against the registry for this id must fail loudly
 * rather than silently match a real metric.
 */
export const DIVIDER_METRIC_ID = "__divider__" as const;

/** Every tile shape the page can render, including the layout-only divider. */
export type TileShape = "stat" | "series" | "breakdown" | "divider";
