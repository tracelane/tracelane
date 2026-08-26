import { cn } from "../lib/cn";

/**
 * BarChart — the app's ONE time-series chart (ADR-074 §5 G3).
 *
 * WHY BARS AND NOT A LINE. Founder call, and it is the right one for this product:
 * every series here is a BUCKET — requests in a 5-minute window, errors per hour, p95
 * over a period. A line implies a continuous signal sampled between points and invites
 * the eye to interpolate across gaps that do not exist. `LatencyTimeline` drew each
 * contiguous run as its own `<polyline>` precisely so the line would not bridge a
 * missing hour; bars make that a property of the form instead of a workaround.
 *
 * Discrete data, discrete marks. A zero bucket is a visible zero, not a dip.
 *
 * COLOUR IS DATA (P0.11). Bars are `--chart-primary` — the ONE data colour, graphite —
 * and take a semantic tone only where the datum CARRIES one: an error count is `danger`,
 * a verified count is `ok`. A second series is `--chart-secondary`, told apart by VALUE
 * and not by hue. Gridlines are `--chart-grid`, which tokens.css calls "barely there on
 * purpose". Nothing here is coloured for decoration, and the highlighted bucket is marked
 * by INK WEIGHT, so the chart still reads in monochrome print and for a red/green-blind
 * reader.
 *
 * RENAMED 2026-08-22 from `fill-info` / `fill-data-2`. Those two tokens were a blue and a
 * violet; the P0 palette swap retargeted them at the chart neutrals, so the RENDER did not
 * change here — only the name did. `chart-primary` says "this is the series"; `info` said
 * "this is a state", which was never what a bar meant.
 *
 * NO DEPENDENCY. Hand-built inline SVG, ~5KB of component. A charting library for one
 * bar chart would be the largest single addition to the bundle in the app.
 *
 * Budget: pure SVG rects, no filters, no gradients on the bars, no per-bar shadow — a
 * 2,000-bucket render is 2,000 rects and nothing else (§9).
 */

export type BarTone = "data" | "ok" | "warn" | "danger" | "second";

export interface BarDatum {
	/** X label. Rendered under the axis at a readable stride, never all at once. */
	label: string;
	value: number;
	/** Overrides the chart tone for THIS bucket — use when the datum carries meaning. */
	tone?: BarTone;
	/** Optional richer tooltip line; falls back to `label · value`. */
	title?: string;
}

const TONE_FILL: Record<BarTone, string> = {
	data: "fill-chart-primary",
	ok: "fill-ok",
	warn: "fill-warn",
	danger: "fill-danger",
	second: "fill-chart-secondary",
};

export interface BarChartProps {
	data: readonly BarDatum[];
	/** Accessible name. Required — a chart with no name is unreadable to a screen reader. */
	label: string;
	/** Chart height in px (the plot area, excluding the axis strip). Default 132. */
	height?: number;
	tone?: BarTone;
	/** Format a value for the axis + tooltip. Default: compact integer. */
	format?: (n: number) => string;
	/** Draw the y-axis max/mid gridlines + labels. Default true. */
	grid?: boolean;
	/** Index of the bucket to emphasise (e.g. the peak). Emphasis is WEIGHT, not hue. */
	highlight?: number;
	className?: string;
}

const AXIS_H = 18;
const Y_LABEL_W = 34;

function compact(n: number): string {
	if (!Number.isFinite(n)) return "—";
	const abs = Math.abs(n);
	if (abs >= 1_000_000)
		return `${(n / 1_000_000).toFixed(abs >= 10_000_000 ? 0 : 1)}M`;
	if (abs >= 1_000) return `${(n / 1_000).toFixed(abs >= 10_000 ? 0 : 1)}k`;
	return String(Math.round(n));
}

export function BarChart({
	data,
	label,
	height = 132,
	tone = "data",
	format = compact,
	grid = true,
	highlight,
	className,
}: BarChartProps) {
	const n = data.length;
	if (n === 0) {
		return (
			<div
				className={cn(
					"flex items-center justify-center rounded-lg border border-line border-dashed text-ink-3 text-xs",
					className,
				)}
				style={{ height: height + AXIS_H }}
			>
				No data in this range
			</div>
		);
	}

	const max = Math.max(...data.map((d) => d.value), 0);
	// A flat-zero series must not render full-height bars. Guard the divisor AND
	// keep the axis honest by showing a real 0 ceiling.
	const ceiling = max > 0 ? max : 1;

	// Bars get the full width minus the y-label gutter; the gap is proportional so a
	// 12-bucket chart and a 200-bucket chart both read as bars rather than a comb.
	const plotW = 1000 - Y_LABEL_W;
	const slot = plotW / n;
	const gap = Math.min(slot * 0.32, 6);
	const barW = Math.max(slot - gap, 0.75);

	// Label stride: never more than ~8 x-labels, and always the first and last.
	const stride = Math.max(1, Math.ceil(n / 8));

	return (
		<figure className={cn("w-full", className)} aria-label={label}>
			<svg
				viewBox={`0 0 1000 ${height + AXIS_H}`}
				width="100%"
				height={height + AXIS_H}
				preserveAspectRatio="none"
				role="img"
				aria-label={label}
				className="overflow-visible"
			>
				<title>{label}</title>

				{grid && (
					<g>
						{[0, 0.5, 1].map((f) => {
							const y = height - f * height;
							return (
								<g key={f}>
									<line
										x1={Y_LABEL_W}
										x2={1000}
										y1={y}
										y2={y}
										className="stroke-chart-grid"
										strokeWidth={1}
										vectorEffect="non-scaling-stroke"
										strokeDasharray={f === 0 ? undefined : "2 3"}
									/>
									<text
										x={Y_LABEL_W - 6}
										y={y + (f === 1 ? 8 : 3)}
										textAnchor="end"
										/* design-constraint-ok: SVG user-space font size, not a DOM font size — it scales with the viewBox, so the ADR-074 §2 DOM ramp does not apply and 11px would collide with tick spacing */
										className="fill-ink-3 font-mono text-[9px]"
										style={{ fontVariantNumeric: "tabular-nums" }}
									>
										{format(ceiling * f)}
									</text>
								</g>
							);
						})}
					</g>
				)}

				{data.map((d, i) => {
					const h = max > 0 ? (d.value / ceiling) * height : 0;
					// Every non-zero bucket keeps at least a 1px stub, so "small" never
					// renders identically to "none" — the distinction the chart exists for.
					const drawn = d.value > 0 ? Math.max(h, 1.5) : 0;
					const x = Y_LABEL_W + i * slot + gap / 2;
					const t = d.tone ?? tone;
					const emphasised = highlight === i;
					return (
						<rect
							key={`${d.label}-${i}`}
							x={x}
							y={height - drawn}
							width={barW}
							height={drawn}
							rx={Math.min(1.5, barW / 2)}
							className={cn(
								TONE_FILL[t],
								// Emphasis by WEIGHT, never by hue — the chart must survive
								// monochrome and colour-blind readers.
								emphasised ? "opacity-100" : "opacity-70",
								"transition-opacity hover:opacity-100",
							)}
						>
							<title>{d.title ?? `${d.label} · ${format(d.value)}`}</title>
						</rect>
					);
				})}

				<g>
					{data.map((d, i) =>
						i % stride === 0 || i === n - 1 ? (
							<text
								key={`${d.label}-x-${i}`}
								x={Y_LABEL_W + i * slot + slot / 2}
								y={height + 13}
								textAnchor={i === 0 ? "start" : i === n - 1 ? "end" : "middle"}
								/* design-constraint-ok: SVG user-space font size, not a DOM font size — it scales with the viewBox, so the ADR-074 §2 DOM ramp does not apply and 11px would collide with tick spacing */
								className="fill-ink-3 font-mono text-[9px]"
								style={{ fontVariantNumeric: "tabular-nums" }}
							>
								{d.label}
							</text>
						) : null,
					)}
				</g>
			</svg>
		</figure>
	);
}
