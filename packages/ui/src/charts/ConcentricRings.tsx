import { cn } from "../lib/cn";

/**
 * ConcentricRings — nested "where the time goes" rings (app design system,
 * docs/design/tracelane-app-full.html screen 1). Outer → inner components of a
 * whole (e.g. end-to-end ⊃ provider ⊃ gateway-overhead latency).
 *
 * Pure presentation: every `value` is a pre-formatted REAL number supplied by
 * the caller — the component fabricates nothing. Ring sizes are a fixed nested
 * metaphor (not proportional); the caller passes a `caption` stating the real
 * relationship (e.g. "gateway = 5% of the trip") so the visual never overclaims.
 */

export interface ConcentricRing {
	/** Pre-formatted real value, e.g. "9.33s" / "444ms" / "—". */
	value: string;
	/** Short label, e.g. "end-to-end". */
	label: string;
}

export interface ConcentricRingsProps {
	/** Outer → inner. 2–3 rings (the innermost is the highlighted lava fill). */
	rings: ConcentricRing[];
	caption?: string;
	className?: string;
}

const OUTER = 176;

export function ConcentricRings({
	rings,
	caption,
	className,
}: ConcentricRingsProps) {
	const n = Math.min(rings.length, 3);
	const shown = rings.slice(0, n);

	return (
		<div className={cn("flex flex-col items-center gap-3", className)}>
			<div className="relative" style={{ width: OUTER, height: OUTER }}>
				{shown.map((r, i) => {
					const size = OUTER - i * 58;
					const top = (OUTER - size) / 2;
					const inner = i === n - 1;
					// Outer→inner tint ramp toward the solid lava core.
					const bg = inner
						? "var(--accent)"
						: i === 0
							? "var(--accent-soft)"
							: "var(--accent-line)";
					// v0-VIZ-REVISIT (founder, 2026-07-20): the inner core value is white
					// on the soft --accent fill (#ff8566) = ~2.4:1, below AA. Kept for v0
					// (ring structure locked; founder revisiting the viz). Band values use
					// --accent-ink (deep lava, AA) and read fine. On the viz rework, give
					// the core number a token that clears AA in BOTH themes.
					const valueColor = inner ? "var(--accent-on)" : "var(--accent-ink)";
					const labelColor = inner ? "var(--accent-on)" : "var(--ink-3)";
					return (
						<div
							key={r.label}
							className="absolute left-1/2 flex -translate-x-1/2 flex-col items-center"
							style={{
								width: size,
								height: size,
								top,
								borderRadius: "50%",
								background: bg,
								justifyContent: inner ? "center" : "flex-start",
								paddingTop: inner ? 0 : 10,
							}}
						>
							<span
								className="font-mono text-[15px] font-semibold leading-none tabular-nums"
								style={{ color: valueColor }}
							>
								{r.value}
							</span>
							{inner && (
								<span
									className="mt-1 text-[10px] leading-none"
									style={{ color: labelColor }}
								>
									{r.label}
								</span>
							)}
						</div>
					);
				})}
			</div>
			{/* Legend — the OUTER ring labels live here, not inside the rings: each
			    inner ring is drawn over the outer ring's label band and was clipping
			    them ("end-to-end" / "provider" were hidden). The innermost ring keeps
			    its own label (nothing overlaps it). */}
			{n > 1 && (
				<ul className="flex flex-wrap items-center justify-center gap-x-3 gap-y-1">
					{shown.slice(0, n - 1).map((r, i) => (
						<li
							key={r.label}
							className="flex items-center gap-1.5 text-[10.5px] text-ink-3"
						>
							<span
								className="h-2 w-2 shrink-0 rounded-full border border-line"
								style={{
									background:
										i === 0 ? "var(--accent-soft)" : "var(--accent-line)",
								}}
							/>
							<span>{r.label}</span>
						</li>
					))}
				</ul>
			)}
			{caption && (
				<p className="text-center text-[11px] text-ink-3">{caption}</p>
			)}
		</div>
	);
}
