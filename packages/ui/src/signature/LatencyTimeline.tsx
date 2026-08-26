import { cn } from "../lib/cn";

/** One hourly bucket. `null` percentiles = a bucket with no traffic — rendered
 *  as an honest GAP (the line breaks; nothing is interpolated across it). */
export interface LatencyPoint {
	/** Short x-axis label, e.g. "05:00". */
	label: string;
	/** Request-weighted percentile latency (ms) for the bucket, or null = no data. */
	p50: number | null;
	p95: number | null;
	p99: number | null;
}

export interface LatencyTimelineProps {
	/** Contiguous hourly buckets, oldest→newest. Empty hours carry null
	 *  percentiles so the gap is visible, never smoothed over. */
	points: LatencyPoint[];
	className?: string;
	/** Accessible description of the chart. */
	ariaLabel?: string;
}

const W = 760;
const H = 210;
const PAD_L = 46;
const PAD_R = 14;
const PAD_T = 14;
const PAD_B = 28;
const PLOT_W = W - PAD_L - PAD_R;
const PLOT_H = H - PAD_T - PAD_B;

function formatMs(ms: number): string {
	if (ms < 1000) return `${Math.round(ms)}ms`;
	return `${(ms / 1000).toFixed(1)}s`;
}

/** Round up to a clean axis ceiling (1/2/5 × 10ⁿ) so tick labels read nicely. */
function niceCeil(v: number): number {
	if (v <= 0) return 1;
	const pow = 10 ** Math.floor(Math.log10(v));
	const n = v / pow;
	const step = n <= 1 ? 1 : n <= 2 ? 2 : n <= 5 ? 5 : 10;
	return step * pow;
}

/**
 * LatencyTimeline — hand-built inline-SVG latency-over-time chart (design system
 * tokens, no charting-lib dependency; sibling to the three signature viz).
 *
 * Draws one RANGE BAR per hourly bucket — p50→p99, with a p95 tick across it.
 * **Real data only:** buckets with no traffic arrive as null percentiles and render as
 * GAPS, so nothing bridges a missing hour and no bucket is interpolated or smoothed.
 *
 * COLOUR (P0.11, 2026-08-22). ONE series, so ONE colour at two weights: the p50–p99
 * body is `--chart-primary` at 35% and the p95 tick is the same token at full strength.
 * A second TOKEN (`--chart-secondary`) would say "second series", and p95 is not a
 * second series — it is the same latency read at a different percentile, which is
 * exactly what a weight step says and a hue step does not. Gridlines are `--chart-grid`,
 * labels `--ink-3`. The classes were `fill-info` (a blue before the palette swap, now
 * the same graphite) and `stroke-line`; the figcaption swatches were `--action-ink` and
 * `--action-soft`, which no longer matched the marks they claim to key.
 */
export function LatencyTimeline({
	points,
	className,
	ariaLabel = "p95 request latency per hour over the last 24 hours",
}: LatencyTimelineProps) {
	const drawable = points.filter((p) => p.p95 != null).length;

	// One real point can't make a line; below two, a chart over-implies a trend.
	// Say so honestly instead of drawing a near-empty axis.
	if (points.length < 2 || drawable < 2) {
		return (
			<p className={cn("text-xs text-ink-3", className)}>
				Not enough hourly data to chart latency yet — needs at least two hours
				with traffic.
			</p>
		);
	}

	const ceil = niceCeil(
		Math.max(...points.map((p) => p.p99 ?? p.p95 ?? p.p50 ?? 0)) * 1.05,
	);
	const n = points.length;
	// Bars occupy SLOTS, not points on a line: each bucket owns a band of the axis, so
	// x is the slot CENTRE and a missing bucket leaves a real hole rather than a
	// stretched segment between its neighbours.
	const slotW = PLOT_W / n;
	const barW = Math.max(Math.min(slotW * 0.62, 14), 2);
	const xOf = (i: number) => PAD_L + (i + 0.5) * slotW;
	const yOf = (v: number) => PAD_T + PLOT_H * (1 - v / ceil);

	// Resolve every bucket to plot coordinates once (null y = gap).
	const pts = points.map((p, i) => ({
		x: xOf(i),
		label: p.label,
		y50: p.p50 == null ? null : yOf(p.p50),
		y95: p.p95 == null ? null : yOf(p.p95),
		y99: p.p99 == null ? null : yOf(p.p99),
	}));

	const ticks = [0, ceil / 2, ceil];

	return (
		<figure className={cn("m-0", className)}>
			<svg
				role="img"
				aria-label={ariaLabel}
				viewBox={`0 0 ${W} ${H}`}
				preserveAspectRatio="none"
				className="h-44 w-full"
			>
				<title>{ariaLabel}</title>

				{/* gridlines + y labels */}
				{ticks.map((t) => (
					<g key={`y-${t}`}>
						<line
							x1={PAD_L}
							x2={W - PAD_R}
							y1={yOf(t)}
							y2={yOf(t)}
							className="stroke-chart-grid"
							strokeWidth={1}
							vectorEffect="non-scaling-stroke"
						/>
						<text
							x={PAD_L - 8}
							y={yOf(t)}
							textAnchor="end"
							dominantBaseline="middle"
							/* design-constraint-ok: SVG user-space font size, not a DOM font size — it scales with the viewBox, so the ADR-074 §2 DOM ramp does not apply and 11px would collide with tick spacing */
							className="fill-ink-3 font-mono text-[10px]"
						>
							{formatMs(t)}
						</text>
					</g>
				))}

				{/*
				  RANGE BARS — p50→p99 per bucket, with a p95 tick. Replaces the former
				  p50–p99 polygon band + p95 `<polyline>` + node dots (founder call:
				  bars, not single-line charts).

				  This is strictly more honest than the line it replaces. Latency per
				  bucket is a DISTRIBUTION, not a value: the old chart drew p95 as a
				  continuous line and had to break it into per-run `<polyline>`s so it
				  would not bridge a missing hour. With bars the gap is simply a bucket
				  with no bar — the form carries the property instead of the workaround.
				  The reader also gets the spread back, which the line threw away.
				*/}
				{pts.map((q) => {
					if (q.y99 == null && q.y50 == null) return null;
					const top = q.y99 ?? q.y95 ?? q.y50;
					const bottom = q.y50 ?? q.y95 ?? q.y99;
					if (top == null || bottom == null) return null;
					const h = Math.max(bottom - top, 1.5);
					return (
						<g key={`bar-${q.x}`}>
							<rect
								x={q.x - barW / 2}
								y={top}
								width={barW}
								height={h}
								rx={Math.min(2, barW / 2)}
								className="fill-chart-primary opacity-35"
							>
								<title>{`${q.label} · p50–p99`}</title>
							</rect>
							{q.y95 != null && (
								<rect
									x={q.x - barW / 2}
									y={q.y95 - 1}
									width={barW}
									height={2}
									rx={1}
									className="fill-chart-primary"
								>
									<title>{`${q.label} · p95`}</title>
								</rect>
							)}
						</g>
					);
				})}

				{/* x labels REMOVED 2026-08-16 — ADR-074 §7: the shared TimeRuler is the
				    one time axis. Three bare labels here would be a second one. */}
			</svg>

			<figcaption className="mt-2 flex flex-wrap items-center gap-x-4 gap-y-1 text-2xs text-ink-3">
				<span className="inline-flex items-center gap-1.5">
					{/* The swatches must be the SAME tokens as the marks, at the SAME
					    weights — a legend keyed to a colour the chart no longer draws is
					    worse than no legend. */}
					<span
						className="inline-block h-0.5 w-3 bg-chart-primary"
						aria-hidden
					/>
					p95 latency
				</span>
				<span className="inline-flex items-center gap-1.5">
					<span
						className="inline-block h-2 w-3 rounded-sm bg-chart-primary/35"
						aria-hidden
					/>
					p50–p99 band
				</span>
				<span>true quantiles per bucket · gaps = no traffic</span>
			</figcaption>
		</figure>
	);
}
