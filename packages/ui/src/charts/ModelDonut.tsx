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
 * COLOUR (P0.11, 2026-08-22). A composition of NEUTRAL categories is told apart by
 * VALUE, never by hue: the ring is `--chart-primary` stepped DOWN in opacity by rank,
 * and the untracked remainder is `--chart-secondary`, the de-emphasised-mark role. There
 * is no categorical palette here and there must not be one — a model is not an outcome,
 * so giving five models five hues would spend on decoration the only signal this system
 * reserves for meaning. The HTML legend maps shade → model → count (+ %) and carries the
 * per-model drill-through, so identity never rests on the shade alone.
 *
 * The ramp was `--action` (the accent, formerly a lava red) until this pass; the opacity
 * steps are unchanged, so a rendered ring keeps its exact rank ordering and only the base
 * colour moved to the token that names what it is.
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
	/**
	 * Semantic tone for this slice (DSH-08). OMIT IT for a composition whose parts
	 * carry no meaning of their own — models, providers — which keeps the neutral
	 * `--chart-primary` opacity ramp and the P0.11 rule that COLOUR IS DATA. Set it only
	 * when the slices ARE outcomes: blocked / warned / allowed. `--danger` on the blocked
	 * arc is not decoration, it is the datum, and the guardrail-verdict donut depends on
	 * this path keeping its semantic colours.
	 */
	tone?: "ok" | "warn" | "danger" | "info";
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

const TONE_VAR = {
	ok: "var(--ok)",
	warn: "var(--warn)",
	danger: "var(--danger)",
	// `info` is the NEUTRAL tone — a slice a caller wants at full strength without
	// claiming an outcome. It names `--chart-primary` directly now; `--info` resolves
	// to the same value but reads as a state, which is the one thing this slice is not.
	info: "var(--chart-primary)",
} as const;

/** Rank ramp — `--chart-primary` stepped DOWN in opacity by index, floor kept legible.
 *  Value, not hue: the categories are models, which carry no meaning of their own, so
 *  the only thing the ring may encode about them is their order. A segment that declares
 *  a `tone` opts OUT of the ramp and is painted at full strength: an outcome colour that
 *  faded with its list position would say the fifth-ranked failure is less of a failure. */
function shade(
	i: number,
	tone?: ModelDonutSegment["tone"],
): { color: string; op: number } {
	if (tone) return { color: TONE_VAR[tone], op: 1 };
	return { color: "var(--chart-primary)", op: Math.max(0.34, 0.85 - i * 0.16) };
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
		/*
		 * `@container` + `@min-[19rem]:flex-row` — A CONTAINER QUERY, NOT A VIEWPORT
		 * ONE, and the distinction is the whole fix.
		 *
		 * THE DEFECT, found by rendering rather than by reading: side by side, the
		 * 120px ring plus the legend's fixed columns (swatch 10px + percent ~24px +
		 * value 48px + three gaps) need ~250px before the LABEL gets a single pixel.
		 * On the dashboard's guardrail card — `lg:col-span-3` of 12, ~236px inside
		 * its padding — the label column resolved to nothing and `truncate` rendered
		 * "blocked" as "b", "redacted" as "ɹ", "warned" as "w" and "allowed" as "".
		 * A legend whose labels are one glyph each is not a legend.
		 *
		 * A viewport breakpoint could not fix it: this component is 4-wide on one
		 * card and 3-wide on another AT THE SAME VIEWPORT, so the thing that has to
		 * change the layout is the CARD's width, which is exactly what a container
		 * query measures. Below 19rem the ring stacks above a full-width legend and
		 * every label has the whole card to sit in.
		 *
		 * THE `@container` MARKER IS ON THE OUTER DIV AND THE QUERY IS ON THE INNER
		 * ONE, AND THAT SPLIT IS THE WHOLE MECHANISM — not a wrapper for spacing.
		 * A container query resolves against the nearest ANCESTOR container; AN
		 * ELEMENT IS NEVER ITS OWN CONTAINER. The first version of this put
		 * `@container` and `@min-[19rem]:flex-row` on the same element, and it
		 * looked right: the guardrail card stacked, which was the bug being fixed.
		 * It stacked because the query matched NOTHING — at any width, including a
		 * 364px card that should have been a row. Verified against the live
		 * stylesheet rather than by eye: the rule
		 * `@container (width >= 19rem){.@min-[19rem]:flex-row{flex-direction:row}}`
		 * was emitted correctly and simply never applied. A layout that is right for
		 * the wrong reason fails the moment the reason is needed.
		 */
		<div className={cn("@container", className)}>
			<div className="flex flex-col items-center gap-4 @min-[19rem]:flex-row">
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
						stroke="var(--chart-fill)"
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
							const { color, op } = shade(i, m.tone);
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
					    arc so the ring reconciles with the true center total.

					    `--chart-secondary` at 0.5, not `--ink-3` at 0.3: "Other" is a DATA
					    mark that must read as de-emphasised, which is precisely the role
					    chart-secondary names, and 0.5 lands it QUIETER against the card than
					    the ramp's 0.34 floor in BOTH themes — composited, light ~#d3d3d3 vs
					    ~#b3b3b4 on white, dark ~#464646 vs ~#606060 on #151619 — so the
					    remainder never outweighs a real model at either end. */}
						{remainder > OTHER_EPS && (
							<circle
								cx={SIZE / 2}
								cy={SIZE / 2}
								r={R}
								fill="none"
								stroke="var(--chart-secondary)"
								strokeOpacity={0.5}
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
						/* design-constraint-ok: SVG user-space font size, not a DOM font size — it scales with the viewBox, so the ADR-074 §2 DOM ramp does not apply and 11px would collide with tick spacing */
						className="fill-[var(--ink)] text-[19px] font-semibold tabular-nums"
					>
						{compact(grand)}
					</text>
					<text
						x={SIZE / 2}
						y={SIZE / 2 + 14}
						textAnchor="middle"
						/* design-constraint-ok: SVG user-space font size, not a DOM font size — it scales with the viewBox, so the ADR-074 §2 DOM ramp does not apply and 11px would collide with tick spacing */
						className="fill-[var(--ink-3)] text-[9px]"
					>
						{centerLabel}
					</text>
				</svg>

				{/* legend */}
				<ul className="min-w-0 flex-1 space-y-1.5">
					{segments.map((m, i) => {
						const pct = denom > 0 ? (m.value / denom) * 100 : 0;
						const { color, op } = shade(i, m.tone);
						const row = (
							<div className="flex items-center gap-2 text-2xs">
								<span
									className="h-2.5 w-2.5 shrink-0 rounded-[3px]"
									style={{ background: color, opacity: op }}
								/>
								{/* `title` so a name long enough to truncate even at full width —
							    `claude-sonnet-4-5-20260514` and friends — is still recoverable
							    on hover. Truncation is now rare rather than total, but a
							    truncated identifier with no way to read it is a dead end. */}
								<span
									title={m.label}
									className="min-w-0 flex-1 truncate font-mono text-ink-2"
								>
									{m.label}
								</span>
								<span className="tabular-nums text-ink-3">
									{pct.toFixed(0)}%
								</span>
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
										className="block rounded hover:bg-surface-2/50 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-focus-ring"
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
							<div className="flex items-center gap-2 text-2xs">
								<span
									className="h-2.5 w-2.5 shrink-0 rounded-[3px]"
									style={{ background: "var(--chart-secondary)", opacity: 0.5 }}
								/>
								<span className="min-w-0 flex-1 truncate text-ink-3">
									Other
								</span>
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
		</div>
	);
}
