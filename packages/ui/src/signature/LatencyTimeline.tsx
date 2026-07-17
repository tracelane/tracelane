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

/** Contiguous runs of elements where `ok` holds — the segments between gaps. */
function segments<T>(arr: T[], ok: (t: T) => boolean): T[][] {
	const out: T[][] = [];
	let cur: T[] = [];
	for (const t of arr) {
		if (ok(t)) {
			cur.push(t);
		} else if (cur.length) {
			out.push(cur);
			cur = [];
		}
	}
	if (cur.length) out.push(cur);
	return out;
}

/**
 * LatencyTimeline — hand-built inline-SVG latency-over-time chart (ADR-045 Neon
 * tokens, no charting-lib dependency; sibling to the three signature viz).
 *
 * Plots the p95 trace-line (the lime `--accent-ink` data-line role) over a faint
 * p50–p99 band, one point per hourly bucket. **Real data only:** buckets with no
 * traffic arrive as null percentiles and render as GAPS — each contiguous run is
 * its own `<polyline>`, so the line never bridges a missing hour and no point is
 * interpolated or smoothed. Colors come only from tokens (lime line,
 * `--accent-soft` band, `--ink-3` labels) — no hardcoded hex.
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
	const xOf = (i: number) => PAD_L + (i / (n - 1)) * PLOT_W;
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
	const labelIdx = [0, Math.floor((n - 1) / 2), n - 1];

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
							{formatMs(t)}
						</text>
					</g>
				))}

				{/* p50–p99 band (per contiguous run; breaks at gaps) */}
				{segments(pts, (q) => q.y50 != null && q.y99 != null)
					.filter((run) => run.length >= 2)
					.map((run) => {
						const top = run.map((q) => `${q.x},${q.y99}`);
						const bottom = [...run].reverse().map((q) => `${q.x},${q.y50}`);
						return (
							<polygon
								key={`band-${run[0]?.x}`}
								points={[...top, ...bottom].join(" ")}
								className="fill-accent-soft"
							/>
						);
					})}

				{/* p95 trace-line (per contiguous run; gaps are real breaks) */}
				{segments(pts, (q) => q.y95 != null)
					.filter((run) => run.length >= 2)
					.map((run) => (
						<polyline
							key={`p95-${run[0]?.x}`}
							points={run.map((q) => `${q.x},${q.y95}`).join(" ")}
							className="fill-none stroke-accent-ink"
							strokeWidth={2}
							strokeLinecap="round"
							strokeLinejoin="round"
							vectorEffect="non-scaling-stroke"
						/>
					))}

				{/* node pins on each real p95 point */}
				{pts.map((q) =>
					q.y95 != null ? (
						<circle
							key={`dot-${q.x}`}
							cx={q.x}
							cy={q.y95}
							r={2.5}
							className="fill-accent-ink"
						/>
					) : null,
				)}

				{/* x labels (first / middle / last) */}
				{labelIdx.map((i) => {
					const q = pts[i];
					if (!q) return null;
					return (
						<text
							key={`x-${i}`}
							x={q.x}
							y={H - 8}
							textAnchor={i === 0 ? "start" : i === n - 1 ? "end" : "middle"}
							className="fill-ink-3 font-mono text-[10px]"
						>
							{q.label}
						</text>
					);
				})}
			</svg>

			<figcaption className="mt-2 flex flex-wrap items-center gap-x-4 gap-y-1 text-[11px] text-ink-3">
				<span className="inline-flex items-center gap-1.5">
					<span className="inline-block h-0.5 w-3 bg-accent-ink" aria-hidden />
					p95 latency
				</span>
				<span className="inline-flex items-center gap-1.5">
					<span
						className="inline-block h-2 w-3 rounded-sm bg-accent-soft"
						aria-hidden
					/>
					p50–p99 band
				</span>
				<span>request-weighted per hour · gaps = no traffic</span>
			</figcaption>
		</figure>
	);
}
