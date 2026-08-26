import { cn } from "../lib/cn";

/**
 * Gauge — a semicircular arc for a rate/coverage metric (app design system,
 * docs/design/tracelane-app-full.html screen 8, "Prompt-cache hit"). An inert track,
 * a neutral progress arc, the real value in the centre, a caption below.
 *
 * Pure presentation: `value` is the real percentage from the caller. An honest
 * 0.0% renders a near-empty arc — never faked.
 *
 * COLOUR (P0.11, 2026-08-22). The arc is `--chart-primary` on a normal card and
 * `--ink-inverse` on an inverse one; the track is `--chart-fill` / the same inverse ink
 * at 0.14. Both were `--action*` roles, which named a BUTTON colour for a data mark.
 *
 * THE ARC IS DELIBERATELY NEVER warn/danger, AND THE REASON IS THAT IT CANNOT KNOW.
 * `marker` is documented below as "the pace line, the SLA target, the budget", and the
 * component is given no SIGN for it. The two live call sites point opposite ways:
 * `apps/web/app/dashboard/page.tsx:1036` is an error-budget burn rate where crossing the
 * marker is BAD, and `apps/web/app/gateway/page.tsx:338` is a prompt-cache hit rate where
 * a higher reading is GOOD (it passes no marker today, which is exactly why nobody has
 * had to answer this). Colouring on `value > marker` would paint a healthy cache red the
 * day someone gives it a target. Supplying the missing direction is a PROP change, which
 * this presentation pass is not allowed to make, so the arc stays neutral and the reader
 * gets above/below from the tick's POSITION. Do not "fix" this by guessing the sign.
 *
 * DSH-08 added two props, both because the dashboard's error-budget card needed a
 * gauge and neither existed: `onInverse` (the card is `--surface-inverse`, and a
 * graphite arc resolves to INK in light — ink on ink is the 1:1 invisibility this repo
 * has shipped once already, see StatCard's `valueCls` note) and `marker` (a value with
 * no threshold drawn is a number in a curve, not an instrument).
 */

export interface GaugeProps {
	/** Real percentage, 0–100. */
	value: number;
	/** Pre-formatted centre display; defaults to `${value.toFixed(1)}%`. */
	display?: string;
	label?: string;
	/**
	 * Optional threshold tick on the arc, 0–100 in the SAME scale as `value` —
	 * the pace line, the SLA target, the budget. Drawn as a hairline across the
	 * band so the reader sees "above/below", not just a magnitude.
	 */
	marker?: number;
	/** Caption for the marker, rendered beside the label. */
	markerLabel?: string;
	/** Render on a `--surface-inverse` card: light arc + light text. */
	onInverse?: boolean;
	className?: string;
}

const CX = 70;
const CY = 78;
const R = 58;

/** Point on the semicircle at fraction f (0 = left/0%, 1 = right/100%). */
function arcPoint(f: number): [number, number] {
	const angle = Math.PI * (1 - f); // π (left) → 0 (right)
	return [CX + R * Math.cos(angle), CY - R * Math.sin(angle)];
}

export function Gauge({
	value,
	display,
	label,
	marker,
	markerLabel,
	onInverse,
	className,
}: GaugeProps) {
	const f = Math.max(0, Math.min(1, value / 100));
	const [ex, ey] = arcPoint(f);
	const text = display ?? `${value.toFixed(1)}%`;
	// On an inverse card the only legible ink IS `--ink-inverse`; `--chart-primary` is
	// the same near-black as the card itself in the light theme.
	const arcStroke = onInverse ? "var(--ink-inverse)" : "var(--chart-primary)";
	// The track is INERT — it carries no value, so it takes `--chart-fill`, the token
	// tokens.css defines for "area fill under a line, and inert bar tracks". On the
	// inverse card it is the same ink as the arc at 0.14: a hardcoded
	// `rgb(255 255 255 / 0.14)` stood here, which is a literal colour in a tokens-only
	// tree and would have stayed white if the inverse surface ever stopped being dark.
	const trackStroke = onInverse ? "var(--ink-inverse)" : "var(--chart-fill)";
	const trackOpacity = onInverse ? 0.14 : 1;

	return (
		<div className={cn("flex flex-col items-center", className)}>
			{/*
			 * 96, not 82 (DSH-08). The arc's baseline is CY=78 and its `round` caps
			 * extend a further half-stroke (6px) to y=84 — so an 82px box ended
			 * INSIDE the caps, and the caption below it was drawn straight through
			 * the left leg of the arc. Rendered, it read "b̶u̶rn rate". The extra 14px
			 * is clearance for the caps, not padding.
			 */}
			<svg
				width="140"
				height="96"
				viewBox="0 0 140 96"
				role="img"
				aria-label={label ? `${label}: ${text}` : text}
			>
				<path
					d={`M ${CX - R} ${CY} A ${R} ${R} 0 0 1 ${CX + R} ${CY}`}
					fill="none"
					stroke={trackStroke}
					strokeOpacity={trackOpacity}
					strokeWidth={12}
					strokeLinecap="round"
				/>
				{f > 0 && (
					<path
						d={`M ${CX - R} ${CY} A ${R} ${R} 0 0 1 ${ex} ${ey}`}
						fill="none"
						stroke={arcStroke}
						strokeWidth={12}
						strokeLinecap="round"
					/>
				)}
				{/* Threshold tick — a radial hairline across the 12px band, drawn LAST so
				    it stays visible when the progress arc has already passed it. */}
				{marker !== undefined &&
					(() => {
						const mf = Math.max(0, Math.min(1, marker / 100));
						const a = Math.PI * (1 - mf);
						const [c, s2] = [Math.cos(a), Math.sin(a)];
						return (
							<line
								x1={CX + (R - 7) * c}
								y1={CY - (R - 7) * s2}
								x2={CX + (R + 7) * c}
								y2={CY - (R + 7) * s2}
								stroke={onInverse ? "var(--ink-inverse)" : "var(--ink)"}
								strokeOpacity={onInverse ? 0.75 : 0.55}
								strokeWidth={1.5}
							/>
						);
					})()}
			</svg>
			<div
				className={cn(
					// Pulls the value up INTO the arc. Moved with the box height above:
					// -40px against a 96px box lands the value at the same optical centre
					// -32px did against 82px.
					//
					// `t-metric-sm` (20px), NOT `t-metric` (28px), AND THIS IS A COUPLING
					// WORTH STATING. The negative pull above is tuned to a 20px line box;
					// when the P0 type ramp took `.t-metric` from 20px to 28px on
					// 2026-08-22 this value grew 40% inside a fixed 116px arc and its
					// digits crossed both legs of the stroke — visible immediately on the
					// render, invisible in the diff, because the class name did not change.
					// `t-metric-sm` restores the size this geometry was measured against.
					// If the arc is ever scaled up, this is the line that moves with it.
					"-mt-10 font-mono t-metric-sm",
					onInverse ? "text-ink-inverse" : "text-ink",
				)}
			>
				{text}
			</div>
			{(label || markerLabel) && (
				<div
					className={cn(
						"mt-1.5 text-2xs",
						onInverse ? "text-ink-inverse opacity-60" : "text-ink-3",
					)}
				>
					{[label, markerLabel].filter(Boolean).join(" · ")}
				</div>
			)}
		</div>
	);
}
