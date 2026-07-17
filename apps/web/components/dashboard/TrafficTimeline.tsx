/**
 * TrafficTimeline — hand-built inline-SVG requests-over-time chart (Neon tokens,
 * no charting-lib dependency; sibling to the design-system `<LatencyTimeline>`).
 *
 * One bar per hourly bucket: full height = requests, the red base = the errored
 * subset. Real counts only — a quiet hour is a genuine zero bar, never hidden.
 * Colors come only from tokens (`--ink-3` requests, `--danger` errors,
 * `--ink-3` labels).
 */

import type { TrafficPoint } from "@/app/slo/latency";
import { EmptyState, cn } from "@tracelanedev/ui";

const W = 760;
const H = 200;
const PAD_L = 44;
const PAD_R = 14;
const PAD_T = 14;
const PAD_B = 26;
const PLOT_W = W - PAD_L - PAD_R;
const PLOT_H = H - PAD_T - PAD_B;

function fmtCount(n: number): string {
	if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
	if (n >= 1000) return `${(n / 1000).toFixed(1)}K`;
	return String(n);
}

/** Round up to a clean axis ceiling (1/2/5 × 10ⁿ). */
function niceCeil(v: number): number {
	if (v <= 0) return 1;
	const pow = 10 ** Math.floor(Math.log10(v));
	const n = v / pow;
	const step = n <= 1 ? 1 : n <= 2 ? 2 : n <= 5 ? 5 : 10;
	return step * pow;
}

export function TrafficTimeline({
	points,
	className,
	ariaLabel = "requests per hour over the last 24 hours",
	hrefFor,
}: {
	points: TrafficPoint[];
	className?: string;
	ariaLabel?: string;
	/**
	 * Optional per-bucket link — when given, each bar becomes a real anchor to
	 * that bucket's traces (e.g. `/traces?since=…&until=…`). Server-rendered, so
	 * the drill-through is a plain navigation, not client state.
	 */
	hrefFor?: (p: TrafficPoint) => string;
}) {
	const withTraffic = points.filter((p) => p.requests > 0).length;
	if (points.length < 2 || withTraffic < 1) {
		return (
			<EmptyState
				title="No traffic data yet"
				description="Requests appear here as they flow through the gateway."
				className={cn("py-8", className)}
			/>
		);
	}

	const ceil = niceCeil(Math.max(...points.map((p) => p.requests)) * 1.05);
	const n = points.length;
	// Bar geometry: even slots across the plot, small gap between bars.
	const slot = PLOT_W / n;
	const barW = Math.max(1, slot * 0.66);
	const yOf = (v: number) => PAD_T + PLOT_H * (1 - v / ceil);
	const ticks = [0, ceil / 2, ceil];
	// Dedupe so n===2 (→ [0,0,1]) doesn't draw a duplicate-keyed, overlapping label.
	const labelIdx = [...new Set([0, Math.floor((n - 1) / 2), n - 1])];

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
							className="stroke-line"
							strokeWidth={1}
							vectorEffect="non-scaling-stroke"
						/>
						<text
							x={PAD_L - 8}
							y={yOf(t)}
							textAnchor="end"
							dominantBaseline="middle"
							className="fill-ink-3 font-mono text-[10px]"
						>
							{fmtCount(t)}
						</text>
					</g>
				))}

				{/* bars: full = requests (neutral ink-3), red base = errors */}
				{points.map((p, i) => {
					const x = PAD_L + i * slot + (slot - barW) / 2;
					const okTop = yOf(p.requests);
					const okH = Math.max(0, yOf(0) - okTop);
					const errH = Math.max(
						0,
						yOf(0) - yOf(Math.min(p.errors, p.requests)),
					);
					const tip = `${p.label} · ${p.requests.toLocaleString()} request${
						p.requests === 1 ? "" : "s"
					}${p.errors > 0 ? ` · ${p.errors.toLocaleString()} errored` : ""}`;
					const inner = (
						<>
							{/* native tooltip on hover — zero JS */}
							<title>{tip}</title>
							<rect
								x={x}
								y={okTop}
								width={barW}
								height={okH}
								rx={1}
								className="fill-ink-3"
								opacity={0.85}
							/>
							{p.errors > 0 && (
								<rect
									x={x}
									y={yOf(0) - errH}
									width={barW}
									height={errH}
									rx={1}
									className="fill-danger"
								/>
							)}
							{/* full-height transparent hit area so short/zero bars stay
							    hoverable + clickable across the whole column */}
							<rect
								x={PAD_L + i * slot}
								y={PAD_T}
								width={slot}
								height={PLOT_H}
								fill="transparent"
							/>
						</>
					);
					return hrefFor ? (
						<a key={p.t} href={hrefFor(p)} className="cursor-pointer">
							{inner}
						</a>
					) : (
						<g key={p.t}>{inner}</g>
					);
				})}

				{/* x labels (first / middle / last) */}
				{labelIdx.map((i) => {
					const p = points[i];
					if (!p) return null;
					const x = PAD_L + i * slot + slot / 2;
					return (
						<text
							key={`x-${i}`}
							x={x}
							y={H - 8}
							textAnchor={i === 0 ? "start" : i === n - 1 ? "end" : "middle"}
							className="fill-ink-3 font-mono text-[10px]"
						>
							{p.label}
						</text>
					);
				})}
			</svg>

			<figcaption className="mt-2 flex flex-wrap items-center gap-x-4 gap-y-1 text-[11px] text-ink-3">
				<span className="inline-flex items-center gap-1.5">
					<span
						className="inline-block h-2 w-3 rounded-sm bg-ink-3"
						aria-hidden
					/>
					requests
				</span>
				<span className="inline-flex items-center gap-1.5">
					<span
						className="inline-block h-2 w-3 rounded-sm bg-danger"
						aria-hidden
					/>
					errors
				</span>
				<span>per hour · real counts, quiet hours = zero</span>
			</figcaption>
		</figure>
	);
}
