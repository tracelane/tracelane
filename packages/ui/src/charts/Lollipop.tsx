import { cn } from "../lib/cn";

/**
 * Lollipop — discrete time-series BARS with real x/y axes + gridlines. (Name kept:
 * it is imported at a live call site and renaming it is churn, not a fix. The mark is
 * a bar as of 2026-08-15; the dot-and-stem it is named after is gone.)
 * (app design system, docs/design/tracelane-app-full.html screen 1, "Traffic
 * over time"). Thin, clean, no wave/blob fill (ADR-053:40 — corrected 2026-08-15
 * from "ADR-051", which is the billing/EE split and carries no design authority;
 * a guard now blocks that mis-citation: scripts/ci/check-adr051-design-miscite.py).
 *
 * COLOUR (P0.11, 2026-08-22). Bars are `--chart-primary` — the ONE data colour. The
 * class was `fill-info` until the P0 palette swap retargeted `--info` from a blue at the
 * SAME chart neutral, so this is a rename, not a repaint: `chart-primary` says "this is
 * the series", where `info` said "this is a state". Gridlines moved from `--line` (the
 * chrome hairline) to `--chart-grid`, which exists for exactly this and is a step
 * quieter, so the axis recedes behind the bars instead of ruling them.
 *
 * The tallest bucket is emphasised by INK WEIGHT, not hue. It was once painted in the
 * retired accent red; P0 makes colour mean something happened, and "this is the biggest
 * bar" is already visible from the bar being the biggest. The split is 1.00 vs 0.70 —
 * against graphite that is #202124 vs an effective ~#636466 on a white card, and #f2f2f2
 * vs an effective ~#b0b0b0 on a dark one, so the hot bucket reads at both ends. It is
 * deliberately the same pair `BarChart` uses, so the app's two bar charts emphasise
 * identically.
 *
 * Pure presentation: `value`s are the real per-bucket counts supplied by the
 * caller; nothing is smoothed or fabricated. An empty bucket (value 0) renders
 * an honest zero-height bar, never a gap-fill.
 */

export interface LollipopPoint {
	/** x-axis label for the bucket, e.g. "20:00". */
	label: string;
	/** Real bucket value (count). */
	value: number;
}

export interface LollipopProps {
	points: LollipopPoint[];
	/** Optional click-through per bucket (plain anchor — no framework dep). */
	hrefFor?: (index: number) => string;
	className?: string;
	ariaLabel?: string;
}

const W = 640;
const H = 176;
const PAD_L = 34;
const PAD_R = 8;
const PAD_T = 16;
const PAD_B = 22;
const PLOT_W = W - PAD_L - PAD_R;
const PLOT_H = H - PAD_T - PAD_B;

/** Round up to a clean axis ceiling (1/2/5 × 10ⁿ). */
function niceCeil(v: number): number {
	if (v <= 0) return 1;
	const pow = 10 ** Math.floor(Math.log10(v));
	const n = v / pow;
	const step = n <= 1 ? 1 : n <= 2 ? 2 : n <= 5 ? 5 : 10;
	return step * pow;
}

/**
 * Compact count for axis + point labels. Production traffic reaches millions;
 * rendering a raw `1234567` overflows the 9px label and collides with its
 * neighbours, so abbreviate above 1K (1.2K / 3.4M / 1.1B).
 */
function compactCount(v: number): string {
	const a = Math.abs(v);
	if (a >= 1_000_000_000)
		return `${(v / 1_000_000_000).toFixed(a >= 10_000_000_000 ? 0 : 1)}B`;
	if (a >= 1_000_000)
		return `${(v / 1_000_000).toFixed(a >= 10_000_000 ? 0 : 1)}M`;
	if (a >= 1_000) return `${(v / 1_000).toFixed(a >= 10_000 ? 0 : 1)}K`;
	return String(v);
}

export function Lollipop({
	points,
	hrefFor,
	className,
	ariaLabel,
}: LollipopProps) {
	const n = points.length;
	const max = Math.max(1, ...points.map((p) => p.value));
	const yMax = niceCeil(max);
	const hotIndex = points.reduce(
		(best, p, i) => (p.value > (points[best]?.value ?? 0) ? i : best),
		0,
	);

	const baseY = PAD_T + PLOT_H;
	/** Width of one bucket's slot on the x axis — the bar is a fraction of it. */
	const slot = PLOT_W / Math.max(1, n);
	const xFor = (i: number) => PAD_L + ((i + 0.5) * PLOT_W) / Math.max(1, n);
	const yFor = (v: number) => baseY - (v / yMax) * PLOT_H;

	// 4 gridlines + baseline; y tick labels at each.
	const ticks = [0, 0.25, 0.5, 0.75, 1];
	// Sparse x labels — about 5 across.
	const xStep = Math.max(1, Math.ceil(n / 5));

	return (
		<svg
			viewBox={`0 0 ${W} ${H}`}
			className={cn("h-auto w-full", className)}
			role="img"
			aria-label={ariaLabel ?? "traffic over time"}
			preserveAspectRatio="xMidYMid meet"
		>
			{/* gridlines + y ticks */}
			{ticks.map((t) => {
				const y = baseY - t * PLOT_H;
				return (
					<g key={t}>
						<line
							x1={PAD_L}
							x2={W - PAD_R}
							y1={y}
							y2={y}
							stroke="var(--chart-grid)"
							strokeWidth={1}
							strokeDasharray={t === 0 ? undefined : "3 3"}
						/>
						<text
							x={PAD_L - 6}
							y={y + 3}
							textAnchor="end"
							/* design-constraint-ok: SVG user-space font size, not a DOM font size — it scales with the viewBox, so the ADR-074 §2 DOM ramp does not apply and 11px would collide with tick spacing */
							className="fill-[var(--ink-3)] text-[9px] tabular-nums"
						>
							{compactCount(Math.round(t * yMax))}
						</text>
					</g>
				);
			})}

			{/* BARS.
			    Founder call 2026-08-15: bars, not a dot-and-stem lollipop. Each point is
			    a BUCKET — requests in a window — so the mark should have the bucket's
			    weight rather than a hairline stem topped by a dot that reads as a
			    scatter point. The drill-through `hrefFor` wrapper is unchanged, so every
			    bucket is still clickable; only the mark changed.

			    Emphasis on the hot bucket is INK WEIGHT (opacity + ink), never hue —
			    ADR-074 §1 spends colour on meaning, and "this is the bucket under your
			    cursor" is not meaning. */}
			{points.map((p, i) => {
				const x = xFor(i);
				const y = yFor(p.value);
				const hot = i === hotIndex && p.value > 0;
				const barW = Math.max(Math.min(slot * 0.6, 16), 2);
				// A non-zero bucket always keeps a visible stub, so "small" never renders
				// identically to "none" — the distinction the chart exists to show.
				const h = p.value > 0 ? Math.max(baseY - y, 1.5) : 0;
				const showLabel = hot || i % xStep === 0;
				const stem = [
					<rect
						key="bar"
						x={x - barW / 2}
						y={baseY - h}
						width={barW}
						height={h}
						rx={Math.min(2, barW / 2)}
						className={cn(
							"fill-chart-primary",
							hot ? "opacity-100" : "opacity-70",
						)}
					/>,
					showLabel ? (
						<text
							key="val"
							x={x}
							y={y - 8}
							textAnchor="middle"
							className={cn(
								"text-2xs font-semibold tabular-nums",
								hot ? "fill-[var(--ink)]" : "fill-[var(--ink-2)]",
							)}
						>
							{compactCount(p.value)}
						</text>
					) : null,
				];
				const href = hrefFor?.(i);
				return href ? (
					<a
						key={`${p.label}-${i}`}
						href={href}
						aria-label={`${p.label}: ${compactCount(p.value)}`}
					>
						{stem}
					</a>
				) : (
					<g key={`${p.label}-${i}`}>{stem}</g>
				);
			})}

			{/* x labels REMOVED 2026-08-16 — ADR-074 §7. The shared `TimeRuler` is the
			    app's one time axis, and a chart that keeps its own strided labels under
			    a ruler is two axes for one dimension. The caller renders the ruler
			    beneath this svg, inset to PAD_L/PAD_R so the ticks land on the slots. */}
		</svg>
	);
}
