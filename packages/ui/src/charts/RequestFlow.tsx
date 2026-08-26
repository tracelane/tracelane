import { cn } from "../lib/cn";

/**
 * RequestFlow — a Sankey of the gateway request path: Gateway → model → outcome
 * (app design system, docs/design/tracelane-app-full.html "request flow").
 *
 * Pure presentation: every width is a REAL count supplied by the caller
 * (per-model requests + errors from the SLO rows). The middle bars are the
 * models; the right bars are the honest outcome split — OK (requests − errors,
 * Verify-green) and Error (errors, danger). Nothing is fabricated: a window with
 * zero errors flows entirely to OK and the Error node collapses to nothing.
 *
 * Labels live in the left/right gutters (Gateway, OK, Error); model identity is
 * carried by the HTML legend below (swatch → name → requests) so the ribbons
 * stay legible at card size.
 *
 * COLOUR (P0.11, 2026-08-22). Two channels, and the split is the whole point:
 *  · ROUTING — gateway → model — carries NO meaning of its own, so it is an OPACITY
 *    ramp on `--chart-primary`, one colour told apart by value. It was a ramp on the
 *    `--action` accent (a lava red before the palette swap), which spent a hue on
 *    "which row of the legend is this".
 *  · OUTCOME — model → OK / Error — IS the meaning, so it keeps `--ok` and `--danger`.
 *    A red ribbon here says a request failed; that is a datum, not decoration.
 * Never a hardcoded hex, in either channel.
 */

export interface RequestFlowModel {
	/** Stable unique key (e.g. `provider::model`); falls back to `label`. */
	id?: string;
	/** Model name, e.g. "claude-haiku-4-5". */
	label: string;
	/** Real request count for this model in the window. */
	requests: number;
	/** Real error count (≤ requests). Success = requests − errors. */
	errors: number;
	/** Optional click-through (plain anchor — no framework dep). */
	href?: string;
}

export interface RequestFlowProps {
	/** Top models by request volume (already sliced/sorted by the caller). */
	models: RequestFlowModel[];
	className?: string;
	ariaLabel?: string;
}

const W = 420;
const H = 188;
const GUT_L = 60; // left gutter — "Gateway" + total
const GUT_R = 62; // right gutter — OK / Error + counts
const PAD_T = 12;
const PAD_B = 12;
const BW = 15; // node bar width
const GAP = 8; // vertical gap between stacked model bars
const PLOT_H = H - PAD_T - PAD_B;

/** Rank ramp for the model routing ribbons/bars — `--chart-primary` stepped down in
 *  opacity, no categorical palette. Models are not outcomes, so the only thing this
 *  channel may encode is order. */
function modelShade(i: number): { fill: string; op: number } {
	// strong→soft by index; floored so later models stay visible.
	return { fill: "var(--chart-primary)", op: Math.max(0.32, 0.62 - i * 0.1) };
}

/** Compact count for the gutter labels (1.2K / 3.4M). */
function compact(v: number): string {
	const a = Math.abs(v);
	if (a >= 1_000_000)
		return `${(v / 1_000_000).toFixed(a >= 10_000_000 ? 0 : 1)}M`;
	if (a >= 1_000) return `${(v / 1_000).toFixed(a >= 10_000 ? 0 : 1)}K`;
	return v.toLocaleString();
}

/** Ribbon path between a left segment [y0a,y1a]@xa and a right segment [y0b,y1b]@xb. */
function ribbon(
	xa: number,
	y0a: number,
	y1a: number,
	xb: number,
	y0b: number,
	y1b: number,
): string {
	const mx = (xa + xb) / 2;
	return `M${xa},${y0a} C${mx},${y0a} ${mx},${y0b} ${xb},${y0b} L${xb},${y1b} C${mx},${y1b} ${mx},${y1a} ${xa},${y1a} Z`;
}

export function RequestFlow({
	models,
	className,
	ariaLabel,
}: RequestFlowProps) {
	const total = models.reduce((s, m) => s + m.requests, 0);
	const totalErrors = models.reduce((s, m) => s + m.errors, 0);
	const totalOk = Math.max(0, total - totalErrors);

	// Column x-positions.
	const gwX = GUT_L;
	const mX = (W - GUT_R + GUT_L) / 2 - BW / 2; // centered model column
	const outX = W - GUT_R - BW;

	// Scale: total requests → PLOT_H minus the inter-bar gaps on the model column.
	const gaps = Math.max(0, models.length - 1) * GAP;
	const scale = total > 0 ? (PLOT_H - gaps) / total : 0;

	// Model bar rects + the running gateway/model offsets for the left ribbons.
	let mCursor = PAD_T;
	let gwCursor = PAD_T;
	const segs = models.map((m, i) => {
		const h = m.requests * scale;
		const gy0 = gwCursor;
		const gy1 = gwCursor + h; // gateway is full-height (no gaps) — same order
		const my0 = mCursor;
		const my1 = mCursor + h;
		gwCursor = gy1;
		mCursor = my1 + GAP;
		return { m, i, h, gy0, gy1, my0, my1 };
	});

	// Outcome bars: OK on top, Error below. Right ribbons split each model bar by
	// its own ok/error share and stack onto the two outcome bars in model order.
	const okH = totalOk * scale;
	const errH = totalErrors * scale;
	const okY0 = PAD_T + (PLOT_H - okH - errH) / 2; // vertically centered stack
	const errY0 = okY0 + okH;
	let okCursor = okY0;
	let errCursor = errY0;

	return (
		<div className={cn("flex flex-col gap-3", className)}>
			<svg
				viewBox={`0 0 ${W} ${H}`}
				className="h-auto w-full"
				role="img"
				aria-label={ariaLabel ?? "request flow: gateway to model to outcome"}
				preserveAspectRatio="xMidYMid meet"
			>
				{/* left ribbons: gateway → model (model shade) */}
				{segs.map(({ m, i, gy0, gy1, my0, my1 }) => {
					const { fill, op } = modelShade(i);
					return (
						<path
							key={`l-${m.id ?? m.label}`}
							d={ribbon(gwX + BW, gy0, gy1, mX, my0, my1)}
							fill={fill}
							fillOpacity={op * 0.55}
						/>
					);
				})}

				{/* right ribbons: model → OK / Error (outcome color) */}
				{segs.map(({ m, my0, my1, h }) => {
					const ok = Math.max(0, m.requests - m.errors);
					const okShare = m.requests > 0 ? (ok / m.requests) * h : 0;
					const errShare = h - okShare;
					const okPath = ribbon(
						mX + BW,
						my0,
						my0 + okShare,
						outX,
						okCursor,
						okCursor + okShare,
					);
					okCursor += okShare;
					const errPath =
						errShare > 0.01
							? ribbon(
									mX + BW,
									my0 + okShare,
									my1,
									outX,
									errCursor,
									errCursor + errShare,
								)
							: null;
					if (errShare > 0.01) errCursor += errShare;
					return (
						<g key={`r-${m.id ?? m.label}`}>
							{/*
							 * THE OK RIBBON IS NEUTRAL, NOT GREEN — the same call the
							 * dashboard's guardrail donut makes, for the same reason.
							 * OK is ~99% of traffic on any healthy fleet, so painting it
							 * `--ok` made the widest band on the card a saturated green
							 * and the LOUDEST object on screen the news that nothing
							 * happened. Under "colour is data" the datum here is the
							 * EXCEPTION: the thin `--danger` ribbon splitting off below.
							 * Neutral OK + red error is both more restrained and more
							 * informative — the eye lands on the failure.
							 */}
							<path d={okPath} fill="var(--chart-primary)" fillOpacity={0.16} />
							{errPath && (
								<path d={errPath} fill="var(--danger)" fillOpacity={0.34} />
							)}
						</g>
					);
				})}

				{/* gateway bar (full height) — the source node, so it is the routing
				    channel at full strength rather than a ramp step. */}
				<rect
					x={gwX}
					y={PAD_T}
					width={BW}
					height={PLOT_H}
					rx={3}
					fill="var(--chart-primary)"
					fillOpacity={0.85}
				/>
				<text
					x={gwX + BW / 2}
					y={PAD_T - 3}
					textAnchor="middle"
					/* design-constraint-ok: SVG user-space font size, not a DOM font size — it scales with the viewBox, so the ADR-074 §2 DOM ramp does not apply and 11px would collide with tick spacing */
					className="fill-[var(--ink-2)] text-[9px] font-semibold"
				>
					Gateway
				</text>
				<text
					x={gwX + BW / 2}
					y={H - 3}
					textAnchor="middle"
					/* design-constraint-ok: SVG user-space font size, not a DOM font size — it scales with the viewBox, so the ADR-074 §2 DOM ramp does not apply and 11px would collide with tick spacing */
					className="fill-[var(--ink-3)] text-[9px] tabular-nums"
				>
					{compact(total)}
				</text>

				{/* model bars */}
				{segs.map(({ m, i, my0, h }) => {
					const { fill, op } = modelShade(i);
					const bar = (
						<rect
							key={`bar-${m.id ?? m.label}`}
							x={mX}
							y={my0}
							width={BW}
							height={Math.max(1, h)}
							rx={3}
							fill={fill}
							fillOpacity={op + 0.2}
						/>
					);
					return m.href ? (
						<a
							key={`b-${m.id ?? m.label}`}
							href={m.href}
							aria-label={`${m.label}: ${compact(m.requests)} requests`}
						>
							{bar}
						</a>
					) : (
						<g key={`b-${m.id ?? m.label}`}>{bar}</g>
					);
				})}

				{/* outcome bars + labels */}
				{okH > 0.5 && (
					<>
						<rect
							x={outX}
							y={okY0}
							width={BW}
							height={okH}
							rx={3}
							fill="var(--chart-primary)"
							fillOpacity={0.55}
						/>
						<text
							x={outX + BW + 5}
							y={okY0 + Math.min(okH, 12)}
							/* design-constraint-ok: SVG user-space font size, not a DOM font size — it scales with the viewBox, so the ADR-074 §2 DOM ramp does not apply and 11px would collide with tick spacing */
							className="fill-[var(--ink-2)] text-[9px] font-semibold"
						>
							OK
						</text>
						<text
							x={outX + BW + 5}
							y={okY0 + Math.min(okH, 12) + 11}
							/* design-constraint-ok: SVG user-space font size, not a DOM font size — it scales with the viewBox, so the ADR-074 §2 DOM ramp does not apply and 11px would collide with tick spacing */
							className="fill-[var(--ink-3)] text-[9px] tabular-nums"
						>
							{compact(totalOk)}
						</text>
					</>
				)}
				{errH > 0.5 && (
					<>
						<rect
							x={outX}
							y={errY0}
							width={BW}
							height={errH}
							rx={3}
							fill="var(--danger)"
							fillOpacity={0.85}
						/>
						<text
							x={outX + BW + 5}
							y={errY0 + 8}
							/* design-constraint-ok: SVG user-space font size, not a DOM font size — it scales with the viewBox, so the ADR-074 §2 DOM ramp does not apply and 11px would collide with tick spacing */
							className="fill-[var(--danger)] text-[9px] font-semibold"
						>
							Error
						</text>
					</>
				)}
			</svg>

			{/* model legend — carries model identity + real request counts (drill-through) */}
			<ul className="flex flex-wrap gap-x-3 gap-y-1">
				{segs.map(({ m, i }) => {
					const pct = total > 0 ? (m.requests / total) * 100 : 0;
					const { fill, op } = modelShade(i);
					const row = (
						<span className="flex items-center gap-1.5 text-2xs text-ink-3">
							<span
								className="h-2 w-2 shrink-0 rounded-full"
								style={{ background: fill, opacity: op + 0.25 }}
							/>
							<span className="font-mono text-ink-2">{m.label}</span>
							<span className="tabular-nums">
								{compact(m.requests)}
								{pct >= 1 ? ` · ${pct.toFixed(0)}%` : ""}
							</span>
						</span>
					);
					return (
						<li key={`lg-${m.id ?? m.label}`}>
							{m.href ? (
								<a
									href={m.href}
									className="rounded hover:underline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-focus-ring"
								>
									{row}
								</a>
							) : (
								row
							)}
						</li>
					);
				})}
			</ul>
		</div>
	);
}
