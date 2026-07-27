import { cn } from "../lib/cn";

/**
 * Lollipop — discrete time-series (dot + stem) with real x/y axes + gridlines
 * (app design system, docs/design/tracelane-app-full.html screen 1, "Traffic
 * over time"). Thin, clean, no wave/blob fill (ADR-051). The tallest bucket is
 * highlighted in lava.
 *
 * Pure presentation: `value`s are the real per-bucket counts supplied by the
 * caller; nothing is smoothed or fabricated. An empty bucket (value 0) renders
 * an honest zero-height stem, never a gap-fill.
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
							stroke="var(--line)"
							strokeWidth={1}
							strokeDasharray={t === 0 ? undefined : "3 3"}
						/>
						<text
							x={PAD_L - 6}
							y={y + 3}
							textAnchor="end"
							className="fill-[var(--ink-3)] text-[9px] tabular-nums"
						>
							{compactCount(Math.round(t * yMax))}
						</text>
					</g>
				);
			})}

			{/* lollipops */}
			{points.map((p, i) => {
				const x = xFor(i);
				const y = yFor(p.value);
				const hot = i === hotIndex && p.value > 0;
				const dotR = hot ? 5 : 4;
				const color = hot ? "var(--accent)" : "var(--ink)";
				const showLabel = hot || i % xStep === 0;
				const stem = [
					<line
						key="stem"
						x1={x}
						x2={x}
						y1={baseY}
						y2={y}
						stroke="var(--line-2)"
						strokeWidth={1.5}
					/>,
					<circle key="dot" cx={x} cy={y} r={dotR} fill={color} />,
					showLabel ? (
						<text
							key="val"
							x={x}
							y={y - 8}
							textAnchor="middle"
							className={cn(
								"text-[9px] font-semibold tabular-nums",
								hot ? "fill-[var(--accent)]" : "fill-[var(--ink-2)]",
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

			{/* x labels */}
			{points.map((p, i) =>
				i % xStep === 0 ? (
					<text
						key={`x-${p.label}-${i}`}
						x={xFor(i)}
						y={H - 6}
						textAnchor="middle"
						className="fill-[var(--ink-3)] text-[9px]"
					>
						{p.label}
					</text>
				) : null,
			)}
		</svg>
	);
}
