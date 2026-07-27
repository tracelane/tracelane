import { cn } from "../lib/cn";

/**
 * Gauge — a semicircular arc for a rate/coverage metric (app design system,
 * docs/design/tracelane-app-full.html screen 8, "Prompt-cache hit"). Track +
 * lava progress arc, the real value in the centre, a caption below.
 *
 * Pure presentation: `value` is the real percentage from the caller. An honest
 * 0.0% renders a near-empty arc — never faked.
 */

export interface GaugeProps {
	/** Real percentage, 0–100. */
	value: number;
	/** Pre-formatted centre display; defaults to `${value.toFixed(1)}%`. */
	display?: string;
	label?: string;
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

export function Gauge({ value, display, label, className }: GaugeProps) {
	const f = Math.max(0, Math.min(1, value / 100));
	const [ex, ey] = arcPoint(f);
	const text = display ?? `${value.toFixed(1)}%`;

	return (
		<div className={cn("flex flex-col items-center", className)}>
			<svg
				width="140"
				height="82"
				viewBox="0 0 140 82"
				role="img"
				aria-label={label ? `${label}: ${text}` : text}
			>
				<path
					d={`M ${CX - R} ${CY} A ${R} ${R} 0 0 1 ${CX + R} ${CY}`}
					fill="none"
					stroke="var(--surface-2)"
					strokeWidth={12}
					strokeLinecap="round"
				/>
				{f > 0 && (
					<path
						d={`M ${CX - R} ${CY} A ${R} ${R} 0 0 1 ${ex} ${ey}`}
						fill="none"
						stroke="var(--accent)"
						strokeWidth={12}
						strokeLinecap="round"
					/>
				)}
			</svg>
			<div className="-mt-8 font-mono text-2xl font-semibold tabular-nums text-ink">
				{text}
			</div>
			{label && <div className="mt-0.5 text-[11px] text-ink-3">{label}</div>}
		</div>
	);
}
