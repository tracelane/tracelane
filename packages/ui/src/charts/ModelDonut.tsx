import { cn } from "../lib/cn";

/**
 * ModelDonut — provider/model call-share as a donut (app design system,
 * docs/design/tracelane-app-full.html "model breakdown").
 *
 * Pure presentation: each segment's angle is a REAL count supplied by the caller
 * (the dashboard's `byModel` request aggregate); the center shows the real total.
 * A single-model window renders one full ring; an empty window is handled by the
 * caller's EmptyState (this component assumes `segments` is non-empty).
 *
 * Segments use a rationed lava-shade ramp (no new categorical palette, no
 * hardcoded hex); the HTML legend maps shade → model → count (+ %) and carries
 * the per-model drill-through.
 */

export interface ModelDonutSegment {
	/** Stable unique key (e.g. `provider::model`); falls back to `label`. */
	id?: string;
	/** Model name, e.g. "claude-haiku-4-5". */
	label: string;
	/** Real request count. */
	value: number;
	/** Optional secondary line, e.g. the provider. */
	sub?: string;
	/** Optional click-through (plain anchor — no framework dep). */
	href?: string;
}

export interface ModelDonutProps {
	segments: ModelDonutSegment[];
	/** Real total (center figure). Defaults to the sum of segment values. */
	total?: number;
	/** Center caption under the total, e.g. "calls". */
	centerLabel?: string;
	className?: string;
	ariaLabel?: string;
}

const SIZE = 132;
const R = 52; // ring radius (stroke centerline)
const STROKE = 20;
const C = 2 * Math.PI * R;

/** Lava-shade ramp — deep→soft by index, floor kept legible. */
function shade(i: number): { color: string; op: number } {
	return { color: "var(--accent)", op: Math.max(0.34, 0.85 - i * 0.16) };
}

function compact(v: number): string {
	const a = Math.abs(v);
	if (a >= 1_000_000)
		return `${(v / 1_000_000).toFixed(a >= 10_000_000 ? 0 : 1)}M`;
	if (a >= 1_000) return `${(v / 1_000).toFixed(a >= 10_000 ? 0 : 1)}K`;
	return v.toLocaleString();
}

export function ModelDonut({
	segments,
	total,
	centerLabel = "calls",
	className,
	ariaLabel,
}: ModelDonutProps) {
	const sum = segments.reduce((s, m) => s + m.value, 0);
	const grand = total ?? sum;
	// Percentages + arc angles are against the TRUE total (`grand`), so the center
	// figure, the ring, and the legend all reconcile. When the caller caps to a
	// top-N whose sum is < grand, the untracked remainder is drawn as one honest
	// "Other" arc + legend row — the ring never overstates that the shown models
	// are 100% of traffic (pre-deploy review finding, 2026-07-26).
	const denom = grand > 0 ? grand : 1;
	const remainder = Math.max(0, grand - sum);
	const OTHER_EPS = 0.5;

	let offset = 0; // running fraction of the circumference
	return (
		<div className={cn("flex items-center gap-4", className)}>
			<svg
				viewBox={`0 0 ${SIZE} ${SIZE}`}
				className="h-auto w-[120px] shrink-0"
				role="img"
				aria-label={ariaLabel ?? "model call share"}
			>
				{/* track */}
				<circle
					cx={SIZE / 2}
					cy={SIZE / 2}
					r={R}
					fill="none"
					stroke="var(--surface-2)"
					strokeWidth={STROKE}
				/>
				{/* segments (rotated so the ring starts at 12 o'clock) */}
				<g transform={`rotate(-90 ${SIZE / 2} ${SIZE / 2})`}>
					{segments.map((m, i) => {
						const frac = m.value / denom;
						const len = frac * C;
						const dash = `${len} ${C - len}`;
						const dashOffset = -offset * C;
						offset += frac;
						const { color, op } = shade(i);
						return (
							<circle
								key={m.id ?? m.label}
								cx={SIZE / 2}
								cy={SIZE / 2}
								r={R}
								fill="none"
								stroke={color}
								strokeOpacity={op}
								strokeWidth={STROKE}
								strokeDasharray={dash}
								strokeDashoffset={dashOffset}
							/>
						);
					})}
					{/* Untracked remainder (models beyond the top-N) — one honest muted
					    arc so the ring reconciles with the true center total. */}
					{remainder > OTHER_EPS && (
						<circle
							cx={SIZE / 2}
							cy={SIZE / 2}
							r={R}
							fill="none"
							stroke="var(--ink-3)"
							strokeOpacity={0.3}
							strokeWidth={STROKE}
							strokeDasharray={`${(remainder / denom) * C} ${C - (remainder / denom) * C}`}
							strokeDashoffset={-offset * C}
						/>
					)}
				</g>
				{/* center total */}
				<text
					x={SIZE / 2}
					y={SIZE / 2 - 1}
					textAnchor="middle"
					className="fill-[var(--ink)] text-[19px] font-semibold tabular-nums"
				>
					{compact(grand)}
				</text>
				<text
					x={SIZE / 2}
					y={SIZE / 2 + 14}
					textAnchor="middle"
					className="fill-[var(--ink-3)] text-[9px]"
				>
					{centerLabel}
				</text>
			</svg>

			{/* legend */}
			<ul className="min-w-0 flex-1 space-y-1.5">
				{segments.map((m, i) => {
					const pct = denom > 0 ? (m.value / denom) * 100 : 0;
					const { color, op } = shade(i);
					const row = (
						<div className="flex items-center gap-2 text-[11px]">
							<span
								className="h-2.5 w-2.5 shrink-0 rounded-[3px]"
								style={{ background: color, opacity: op }}
							/>
							<span className="min-w-0 flex-1 truncate font-mono text-ink-2">
								{m.label}
							</span>
							<span className="tabular-nums text-ink-3">{pct.toFixed(0)}%</span>
							<span className="w-12 text-right tabular-nums text-ink">
								{compact(m.value)}
							</span>
						</div>
					);
					return (
						<li key={m.id ?? m.label}>
							{m.href ? (
								<a
									href={m.href}
									className="block rounded hover:bg-surface-2/50 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-seal"
								>
									{row}
								</a>
							) : (
								row
							)}
						</li>
					);
				})}
				{remainder > OTHER_EPS && (
					<li>
						<div className="flex items-center gap-2 text-[11px]">
							<span
								className="h-2.5 w-2.5 shrink-0 rounded-[3px]"
								style={{ background: "var(--ink-3)", opacity: 0.4 }}
							/>
							<span className="min-w-0 flex-1 truncate text-ink-3">Other</span>
							<span className="tabular-nums text-ink-3">
								{((remainder / denom) * 100).toFixed(0)}%
							</span>
							<span className="w-12 text-right tabular-nums text-ink-2">
								{compact(remainder)}
							</span>
						</div>
					</li>
				)}
			</ul>
		</div>
	);
}
